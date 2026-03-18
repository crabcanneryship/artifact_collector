//go:build windows

// Package ntfs は \\.\X: を Raw で開き、NTFS 構造を直接解析してファイル内容を返す。
//
// 処理フロー:
//  1. CreateFile (FILE_FLAG_NO_BUFFERING) でボリュームを開く
//  2. FSCTL_GET_NTFS_VOLUME_DATA でパラメータ取得
//  3. MFT inode 0 のデータランから MFT 全体を読み込む
//  4. MFT を線形走査し $FILE_NAME 属性で目的 inode を解決
//  5. inode の $DATA 属性 (常駐/非常駐) からファイル内容を返す
package ntfs

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Win32 定数 ──────────────────────────────────────────────────────────────

const (
	fileFlagNoBuffering = 0x20000000
	fileFlagBackupSem   = 0x02000000
	genericRead         = 0x80000000
	fileShareReadWrite  = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
	fsctlGetNtfsVolData = 0x00090064 // FSCTL_GET_NTFS_VOLUME_DATA
)

// ── NTFS_VOLUME_DATA_BUFFER (抜粋) ─────────────────────────────────────────

type ntfsVolumeData struct {
	VolumeSerialNumber           int64
	NumberSectors                int64
	TotalClusters                int64
	FreeClusters                 int64
	TotalReserved                int64
	BytesPerSector               uint32
	BytesPerCluster              uint32
	BytesPerFileRecordSegment    uint32
	ClustersPerFileRecordSegment uint32
	MftValidDataLength           int64
	MftStartLcn                  int64
	Mft2StartLcn                 int64
	MftZoneStart                 int64
	MftZoneEnd                   int64
}

// ── VolumeHandle ─────────────────────────────────────────────────────────────

// VolumeHandle はオープンしたボリュームハンドルと NTFS メタデータを保持する。
type VolumeHandle struct {
	handle             windows.Handle
	bytesPerSector     uint64
	bytesPerCluster    uint64
	mftStartLCN        uint64
	bytesPerFileRecord uint64
}

// Open は \\.\<volume> を FILE_FLAG_NO_BUFFERING で開き VolumeHandle を返す。
func Open(volume string) (*VolumeHandle, error) {
	vol := strings.TrimRight(volume, `\`)
	// volume は "C" (コロンなし) または "C:" どちらでも受け付ける
	if !strings.HasSuffix(vol, ":") {
		vol = vol + ":"
	}
	path := `\\.\` + vol

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := windows.CreateFile(
		pathPtr,
		genericRead,
		fileShareReadWrite,
		nil,
		windows.OPEN_EXISTING,
		fileFlagNoBuffering,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("ボリュームオープン失敗 %s: %w", path, err)
	}

	var data ntfsVolumeData
	var returned uint32
	err = windows.DeviceIoControl(
		handle,
		fsctlGetNtfsVolData,
		nil, 0,
		(*byte)(unsafe.Pointer(&data)),
		uint32(unsafe.Sizeof(data)),
		&returned,
		nil,
	)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("FSCTL_GET_NTFS_VOLUME_DATA 失敗: %w", err)
	}

	log.Printf("[DEBUG] NTFS: BytesPerSector=%d BytesPerCluster=%d BytesPerFileRecord=%d MftStartLCN=%d",
		data.BytesPerSector, data.BytesPerCluster,
		data.BytesPerFileRecordSegment, data.MftStartLcn)

	return &VolumeHandle{
		handle:             handle,
		bytesPerSector:     uint64(data.BytesPerSector),
		bytesPerCluster:    uint64(data.BytesPerCluster),
		mftStartLCN:        uint64(data.MftStartLcn),
		bytesPerFileRecord: uint64(data.BytesPerFileRecordSegment),
	}, nil
}

// Close はボリュームハンドルを閉じる。
func (v *VolumeHandle) Close() {
	windows.CloseHandle(v.handle)
}

// ── Raw 読み取り ──────────────────────────────────────────────────────────────

// readRaw は offset バイトから length バイトを読み取る。
// FILE_FLAG_NO_BUFFERING のためセクタ境界にアライメントして読み、必要な範囲を返す。
func (v *VolumeHandle) readRaw(offset, length uint64) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	sector := v.bytesPerSector
	alignedOffset := (offset / sector) * sector
	prefix := offset - alignedOffset
	rawLen := ((prefix + length + sector - 1) / sector) * sector

	_, err := windows.Seek(v.handle, int64(alignedOffset), 0 /* io.SeekStart */)
	if err != nil {
		return nil, fmt.Errorf("シーク失敗 offset=%d: %w", alignedOffset, err)
	}

	buf := make([]byte, rawLen)
	var bytesRead uint32
	err = windows.ReadFile(v.handle, buf, &bytesRead, nil)
	if err != nil && err != syscall.ERROR_HANDLE_EOF {
		return nil, fmt.Errorf("ReadFile 失敗 offset=%d len=%d: %w", alignedOffset, rawLen, err)
	}

	end := prefix + length
	if end > uint64(bytesRead) {
		end = uint64(bytesRead)
	}
	return buf[prefix:end], nil
}

// ── MFT レコード読み取り ──────────────────────────────────────────────────────

func (v *VolumeHandle) readFileRecord(inode uint64) ([]byte, error) {
	mftOffset := v.mftStartLCN * v.bytesPerCluster
	recordOffset := mftOffset + inode*v.bytesPerFileRecord
	return v.readRaw(recordOffset, v.bytesPerFileRecord)
}

// readMFTData は inode 0 ($MFT) のデータランから MFT 全体を読み込む。
func (v *VolumeHandle) readMFTData() ([]byte, error) {
	record, err := v.readFileRecord(0)
	if err != nil {
		return nil, fmt.Errorf("MFT inode 0 読み取り失敗: %w", err)
	}

	runs, err := parseDataRuns(record, v.bytesPerFileRecord)
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return getResidentData(record)
	}

	realSize := getNonResidentDataSize(record)
	var out []byte
	for _, run := range runs {
		offset := run.LCN * v.bytesPerCluster
		length := run.Clusters * v.bytesPerCluster
		chunk, err := v.readRaw(offset, length)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if realSize > 0 && uint64(len(out)) >= realSize {
			break
		}
	}
	if realSize > 0 && uint64(len(out)) > realSize {
		out = out[:realSize]
	}
	// 各MFTレコードにUSA fixupを適用する
	applyUSAFixupToMFT(out, v.bytesPerFileRecord)
	return out, nil
}

// applyUSAFixupToMFT はMFT全体の各レコードにUSA fixupを適用する。
func applyUSAFixupToMFT(mftData []byte, recordSize uint64) {
	total := uint64(len(mftData)) / recordSize
	for i := uint64(0); i < total; i++ {
		start := i * recordSize
		end := start + recordSize
		if end > uint64(len(mftData)) {
			break
		}
		record := mftData[start:end]
		if len(record) >= 4 && string(record[0:4]) == "FILE" {
			applyUSAFixup(record) // in-place: mftDataのスライスを直接変更
		}
	}
}

// ── ファイル検索・内容取得 ────────────────────────────────────────────────────

// ReadFileByPath はボリューム相対パス (例: "$MFT", "Windows\\System32\\config\\SYSTEM")
// からファイル内容を返す。
func (v *VolumeHandle) ReadFileByPath(relPath string) ([]byte, error) {
	if strings.EqualFold(relPath, "$MFT") {
		log.Println("[DEBUG] $MFT: inode 0 から直接読み取り")
		return v.readMFTData()
	}

	log.Println("[DEBUG] MFT 全体を読み込み中...")
	mftData, err := v.readMFTData()
	if err != nil {
		return nil, fmt.Errorf("MFT 読み込み失敗: %w", err)
	}
	log.Printf("[DEBUG] MFT 読み込み完了: %d bytes (%d レコード)",
		len(mftData), uint64(len(mftData))/v.bytesPerFileRecord)

	targetInode, err := findInodeByPath(mftData, relPath, v.bytesPerFileRecord)
	if err != nil {
		return nil, err
	}
	log.Printf("[DEBUG] inode 発見: %s → %d", relPath, targetInode)

	recStart := targetInode * v.bytesPerFileRecord
	recEnd := recStart + v.bytesPerFileRecord
	if recEnd > uint64(len(mftData)) {
		return nil, fmt.Errorf("inode %d のレコードが MFT 範囲外", targetInode)
	}
	record := mftData[recStart:recEnd]

	return v.readFileData(record)
}

func (v *VolumeHandle) readFileData(record []byte) ([]byte, error) {
	runs, err := parseDataRuns(record, v.bytesPerFileRecord)
	if err == nil && len(runs) > 0 {
		realSize := getNonResidentDataSize(record)
		var out []byte
		for _, run := range runs {
			offset := run.LCN * v.bytesPerCluster
			length := run.Clusters * v.bytesPerCluster
			chunk, err := v.readRaw(offset, length)
			if err != nil {
				return nil, err
			}
			out = append(out, chunk...)
			if realSize > 0 && uint64(len(out)) >= realSize {
				break
			}
		}
		if realSize > 0 && uint64(len(out)) > realSize {
			out = out[:realSize]
		}
		return out, nil
	}
	return getResidentData(record)
}

// ── NTFS ファイルレコードパーサ ───────────────────────────────────────────────

type dataRun struct {
	LCN      uint64
	Clusters uint64
}

// applyUSAFixup はMFTレコードのUpdate Sequence Array (USA) 修正を適用する。
// NTFSはディスク書き込み時に各512Bセクタ末尾2Bを USA エントリで上書きする。
// 読み取り後にこれを元の値に戻さないと属性データが破損した状態になる。
// record はコピーを渡すこと (in-place 変更される)。
func applyUSAFixup(record []byte) bool {
	if len(record) < 8 {
		return false
	}
	// +0x04: USA オフセット (2B)
	// +0x06: USA エントリ数 (シーケンス番号 + セクタ数)
	usaOffset := int(binary.LittleEndian.Uint16(record[4:6]))
	usaCount := int(binary.LittleEndian.Uint16(record[6:8]))
	if usaOffset < 8 || usaCount < 2 || usaOffset+usaCount*2 > len(record) {
		return false
	}
	// USA[0] = シーケンス番号 (各セクタ末尾に書かれているはず)
	seqNum := binary.LittleEndian.Uint16(record[usaOffset:])
	// USA[1..] = 各セクタの元の値 (セクタ数 = usaCount-1)
	for i := 1; i < usaCount; i++ {
		sectorEnd := i*512 - 2
		if sectorEnd+2 > len(record) {
			break
		}
		// セクタ末尾のシーケンス番号を確認
		if binary.LittleEndian.Uint16(record[sectorEnd:]) != seqNum {
			// 不一致: レコードが壊れているかUSA不要なデータ
			continue
		}
		// 元の値を復元
		orig := binary.LittleEndian.Uint16(record[usaOffset+i*2:])
		binary.LittleEndian.PutUint16(record[sectorEnd:], orig)
	}
	return true
}

func isValidFileRecord(record []byte) bool {
	return len(record) >= 4 && string(record[0:4]) == "FILE"
}

// parseDataRuns は $DATA 属性 (type=0x80) のデータランを返す。
// 常駐の場合は空スライスを返す。
// collectDataRuns は $ATTRIBUTE_LIST を考慮してレコード(群)から全 $DATA dataRun を収集する。
// Session メソッドとして実装し、vol.readRaw で $ATTRIBUTE_LIST データを直接読める。
func (s *Session) collectDataRuns(record []byte) ([]dataRun, uint64, error) {
	// まず同一レコード内の $DATA を探す
	runs, err := parseDataRuns(record, s.recordSize)
	if err != nil {
		return nil, 0, err
	}
	realSize := getNonResidentDataSize(record)
	if len(runs) > 0 {
		return runs, realSize, nil
	}

	// $DATA なし → $ATTRIBUTE_LIST を探す
	// 1. 常駐 $ATTRIBUTE_LIST
	if attrListData := getAttributeListData(record); attrListData != nil {
		return s.scanAttrList(attrListData)
	}

	// 2. 非常駐 $ATTRIBUTE_LIST → vol.readRaw で読む
	attrListRuns := findAttributeListRuns(record)
	if len(attrListRuns) == 0 {
		return nil, 0, nil // 常駐データ or ファイルなし
	}
	attrListData, err := s.readRunsRaw(attrListRuns)
	if err != nil || len(attrListData) == 0 {
		return nil, 0, nil
	}
	return s.scanAttrList(attrListData)
}

// scanAttrList は $ATTRIBUTE_LIST データを走査して $DATA (0x80) の dataRun を収集する。
func (s *Session) scanAttrList(data []byte) ([]dataRun, uint64, error) {
	var allRuns []dataRun
	var foundSize uint64
	for pos := 0; pos+26 <= len(data); {
		attrType := binary.LittleEndian.Uint32(data[pos : pos+4])
		entryLen := int(binary.LittleEndian.Uint16(data[pos+4 : pos+6]))
		if entryLen == 0 {
			break
		}
		if attrType == 0x80 { // $DATA
			ref := binary.LittleEndian.Uint64(data[pos+0x10 : pos+0x18])
			extInode := ref & 0x0000FFFFFFFFFFFF
			extRecord := getRecordByInode(s.mftData, extInode, s.recordSize)
			if extRecord != nil {
				extRuns, _ := parseDataRuns(extRecord, s.recordSize)
				if len(extRuns) > 0 {
					allRuns = append(allRuns, extRuns...)
					if foundSize == 0 {
						foundSize = getNonResidentDataSize(extRecord)
					}
				}
			}
		}
		pos += entryLen
	}
	return allRuns, foundSize, nil
}

// readRunsRaw は dataRun リストをボリュームから直接読んで結合する。
func (s *Session) readRunsRaw(runs []dataRun) ([]byte, error) {
	var out []byte
	for _, run := range runs {
		offset := run.LCN * s.handle.bytesPerCluster
		length := run.Clusters * s.handle.bytesPerCluster
		chunk, err := s.handle.readRaw(offset, length)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
	}
	return out, nil
}

// findAttributeListRuns は MFTレコードから $ATTRIBUTE_LIST (0x20) の dataRun を返す。
// 常駐の場合は空スライスを返し attrListData に直接データを書く (TODO: 常駐対応は省略)。
func findAttributeListRuns(record []byte) []dataRun {
	if len(record) < 0x18 {
		return nil
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset
	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x20 { // $ATTRIBUTE_LIST
			nonRes := record[pos+8]
			if nonRes == 0 {
				// 常駐: 直接データを返す (dataRunなし)
				return []dataRun{{LCN: 0, Clusters: 0}} // sentinel
			}
			if pos+0x22 <= len(record) {
				runOff := int(binary.LittleEndian.Uint16(record[pos+0x20 : pos+0x22]))
				if runOff > 0 && pos+runOff <= len(record) {
					runs, _ := decodeDataRuns(record[pos+runOff : pos+attrLen])
					return runs
				}
			}
		}
		pos += attrLen
	}
	return nil
}

// getAttributeListData は常駐 $ATTRIBUTE_LIST のデータを返す。
func getAttributeListData(record []byte) []byte {
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset
	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x20 && record[pos+8] == 0 && pos+0x16 <= len(record) {
			contOff := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
			contLen := int(binary.LittleEndian.Uint32(record[pos+0x10 : pos+0x14]))
			s := pos + contOff
			if s+contLen <= len(record) {
				return record[s : s+contLen]
			}
		}
		pos += attrLen
	}
	return nil
}

// getRecordByInode は MFTキャッシュから実inode番号でレコードを返す。
func getRecordByInode(mftData []byte, inode uint64, recordSize uint64) []byte {
	// 高速パス
	start := inode * recordSize
	end := start + recordSize
	if end <= uint64(len(mftData)) {
		record := mftData[start:end]
		if isValidFileRecord(record) && len(record) >= 0x30 {
			if uint64(binary.LittleEndian.Uint32(record[0x2C:0x30])) == inode {
				return record
			}
		}
	}
	// 線形スキャン
	total := uint64(len(mftData)) / recordSize
	for i := uint64(0); i < total; i++ {
		s := i * recordSize
		e := s + recordSize
		if e > uint64(len(mftData)) {
			break
		}
		record := mftData[s:e]
		if !isValidFileRecord(record) || len(record) < 0x30 {
			continue
		}
		if uint64(binary.LittleEndian.Uint32(record[0x2C:0x30])) == inode {
			return record
		}
	}
	return nil
}

func parseDataRuns(record []byte, _ uint64) ([]dataRun, error) {
	if !isValidFileRecord(record) {
		return nil, fmt.Errorf("無効な FILE レコードシグネチャ")
	}
	if len(record) < 0x18 {
		return nil, fmt.Errorf("FILE レコードが短すぎます")
	}

	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}

		if attrType == 0x80 { // $DATA
			nonResident := record[pos+8]
			if nonResident == 0 {
				return nil, nil // 常駐
			}
			// 非常駐属性: Data runs offset は +0x20 から uint16 で読む
			if pos+0x22 > len(record) {
				break
			}
			runOffset := int(binary.LittleEndian.Uint16(record[pos+0x20 : pos+0x22]))
			if runOffset == 0 || pos+runOffset > len(record) {
				break
			}
			runs, err := decodeDataRuns(record[pos+runOffset : pos+attrLen])
			return runs, err
		}
		pos += attrLen
	}
	return nil, nil
}

// decodeDataRuns はデータランバイト列を (絶対LCN, クラスタ数) リストにデコードする。
func decodeDataRuns(data []byte) ([]dataRun, error) {
	var runs []dataRun
	pos := 0
	var currentLCN int64

	for pos < len(data) {
		header := data[pos]
		if header == 0 {
			break
		}
		pos++

		lenBytes := int(header & 0x0F)
		offsetBytes := int(header >> 4)

		if pos+lenBytes+offsetBytes > len(data) {
			break
		}

		// クラスタ数 (符号なし)
		var clusterCount uint64
		for i := 0; i < lenBytes; i++ {
			clusterCount |= uint64(data[pos+i]) << (i * 8)
		}
		pos += lenBytes

		// LCN デルタ (符号付き)
		var lcnDelta int64
		for i := 0; i < offsetBytes; i++ {
			lcnDelta |= int64(data[pos+i]) << (i * 8)
		}
		// 符号拡張
		if offsetBytes > 0 && data[pos+offsetBytes-1]&0x80 != 0 {
			lcnDelta |= ^((int64(1) << (offsetBytes * 8)) - 1)
		}
		pos += offsetBytes

		currentLCN += lcnDelta
		runs = append(runs, dataRun{LCN: uint64(currentLCN), Clusters: clusterCount})
	}
	return runs, nil
}

// getResidentData は常駐 $DATA 属性のデータ本体を返す。
func getResidentData(record []byte) ([]byte, error) {
	if !isValidFileRecord(record) {
		return nil, fmt.Errorf("無効な FILE レコード")
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}

		if attrType == 0x80 && record[pos+8] == 0 {
			if pos+0x16 <= len(record) {
				contentOffset := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
				contentLength := int(binary.LittleEndian.Uint32(record[pos+0x10 : pos+0x14]))
				start := pos + contentOffset
				end := start + contentLength
				if end <= len(record) {
					result := make([]byte, contentLength)
					copy(result, record[start:end])
					return result, nil
				}
			}
		}
		pos += attrLen
	}
	return nil, fmt.Errorf("常駐 $DATA 属性が見つかりません")
}

// getNonResidentDataSize は非常駐 $DATA の実データサイズを返す。0 は不明を意味する。
func getNonResidentDataSize(record []byte) uint64 {
	if len(record) < 0x18 {
		return 0
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x80 && record[pos+8] == 1 && pos+0x38 <= len(record) {
			// real size @ +0x30 (8B)
			return binary.LittleEndian.Uint64(record[pos+0x30 : pos+0x38])
		}
		pos += attrLen
	}
	return 0
}

// ── MFT 走査: パス → inode 解決 ──────────────────────────────────────────────

func findInodeByPath(mftData []byte, relPath string, recordSize uint64) (uint64, error) {
	components := splitPath(relPath)
	// NTFS ルートディレクトリは inode 5
	parentInode := uint64(5)

	for _, component := range components {
		inode, err := findChildInode(mftData, parentInode, component, recordSize)
		if err != nil {
			return 0, fmt.Errorf("'%s' が見つかりません (parent inode=%d): %w",
				component, parentInode, err)
		}
		parentInode = inode
	}
	return parentInode, nil
}

func findChildInode(mftData []byte, parentInode uint64, name string, recordSize uint64) (uint64, error) {
	totalRecords := uint64(len(mftData)) / recordSize

	for i := uint64(0); i < totalRecords; i++ {
		start := i * recordSize
		end := start + recordSize
		if end > uint64(len(mftData)) {
			break
		}
		record := mftData[start:end]

		if !isValidFileRecord(record) {
			continue
		}
		if len(record) < 0x30 {
			continue
		}
		// フラグ bit0 = 使用中
		flags := binary.LittleEndian.Uint16(record[0x16:0x18])
		if flags&0x01 == 0 {
			continue
		}

		if checkFileNameAttr(record, parentInode, name) {
			// MFTレコード +0x2C に記録された実inode番号を返す。
			// 配列インデックス i ではなくレコード内の値を使うことで、
			// MFT断片化環境でも正しい親inodeを追跡できる。
			actualInode := uint64(binary.LittleEndian.Uint32(record[0x2C:0x30]))
			return actualInode, nil
		}
	}
	return 0, fmt.Errorf("'%s' (parent=%d) が MFT 内に見つかりません", name, parentInode)
}

// checkFileNameAttr は $FILE_NAME 属性 (0x30) で親 inode とファイル名を照合する。
// NTFSは1ファイルに複数の $FILE_NAME 属性を持つ場合がある (Win32名/DOS短縮名/POSIX名)。
// いずれか1つでも一致すれば true を返す。
func checkFileNameAttr(record []byte, parentInode uint64, name string) bool {
	if len(record) < 0x18 {
		return false
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}

		if attrType == 0x30 { // $FILE_NAME
			// 複数の $FILE_NAME 属性を全て確認し、どれか一致すれば即 true
			if matchFileNameAttr(record, pos, parentInode, name) {
				return true
			}
		}
		pos += attrLen
	}
	return false
}

// matchFileNameAttr は pos から始まる $FILE_NAME 属性1つを照合する。
// $FILE_NAME 属性の構造:
//
//	属性ヘッダ (pos): type(4) len(4) nonResident(1) nameLen(1) nameOffset(2) flags(2) id(2)
//	常駐ヘッダ (pos+0x10): contentLen(4) contentOffset(2) ...
//	コンテンツ:
//	  +0x00: 親MFT参照 (8B: 下位48bit=inode番号)
//	  +0x40: ファイル名長 (1B, UTF-16文字数)
//	  +0x41: 名前空間 (1B: 0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS)
//	  +0x42: ファイル名 (UTF-16LE)
func matchFileNameAttr(record []byte, pos int, parentInode uint64, name string) bool {
	if pos+0x16 > len(record) {
		return false
	}
	contentOffset := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
	cs := pos + contentOffset

	if cs+0x42 > len(record) {
		return false
	}

	parRef := binary.LittleEndian.Uint64(record[cs : cs+8])
	par := parRef & 0x0000FFFFFFFFFFFF

	nameLen := int(record[cs+0x40])
	nameStart := cs + 0x42
	nameEnd := nameStart + nameLen*2
	if nameEnd > len(record) {
		return false
	}

	utf16 := make([]uint16, nameLen)
	for i := range utf16 {
		utf16[i] = binary.LittleEndian.Uint16(record[nameStart+i*2:])
	}
	fname := windows.UTF16ToString(utf16)

	return par == parentInode && strings.EqualFold(fname, name)
}

func splitPath(p string) []string {
	var parts []string
	for _, s := range strings.FieldsFunc(p, func(r rune) bool {
		return r == '\\' || r == '/'
	}) {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

// ── collector パッケージ向け公開 API ─────────────────────────────────────────

// MatchEntry はMFT走査でマッチしたエントリを表す。
type MatchEntry struct {
	Name  string
	Inode uint64
}

// BytesPerFileRecord はMFTレコードサイズを返す。
func (v *VolumeHandle) BytesPerFileRecord() uint64 {
	return v.bytesPerFileRecord
}

// ReadMFT はMFT全体をバイト列で返す。
func (v *VolumeHandle) ReadMFT() ([]byte, error) {
	return v.readMFTData()
}

// ReadFileByInode は指定 inode のファイル内容を返す。
// mftData は ReadMFT() で取得済みのものを渡す。
func (v *VolumeHandle) ReadFileByInode(mftData []byte, inode uint64) ([]byte, error) {
	recStart := inode * v.bytesPerFileRecord
	recEnd := recStart + v.bytesPerFileRecord
	if recEnd > uint64(len(mftData)) {
		return nil, fmt.Errorf("inode %d のレコードが MFT 範囲外", inode)
	}
	return v.readFileData(mftData[recStart:recEnd])
}

// FindChildInode は parentInode 直下の name に一致するエントリの inode を返す。
func FindChildInode(mftData []byte, parentInode uint64, name string, recordSize uint64) (uint64, error) {
	return findChildInode(mftData, parentInode, name, recordSize)
}

// FindChildrenMatchingFiles は parentInode 直下でパターンにマッチする
// ファイル (非ディレクトリ) を列挙して返す。
func FindChildrenMatchingFiles(mftData []byte, parentInode uint64, pattern string, recordSize uint64) []MatchEntry {
	return findChildrenMatching(mftData, parentInode, pattern, recordSize, false)
}

// FindChildrenMatchingDirs は parentInode 直下でパターンにマッチする
// ディレクトリを列挙して返す。
func FindChildrenMatchingDirs(mftData []byte, parentInode uint64, pattern string, recordSize uint64) []MatchEntry {
	return findChildrenMatching(mftData, parentInode, pattern, recordSize, true)
}

// findChildrenMatching は内部実装。dirsOnly=true でディレクトリのみ、false でファイルのみ返す。
func findChildrenMatching(
	mftData []byte,
	parentInode uint64,
	pattern string,
	recordSize uint64,
	dirsOnly bool,
) []MatchEntry {
	totalRecords := uint64(len(mftData)) / recordSize
	var found []MatchEntry

	for i := uint64(0); i < totalRecords; i++ {
		start := i * recordSize
		end := start + recordSize
		if end > uint64(len(mftData)) {
			break
		}
		record := mftData[start:end]

		if !isValidFileRecord(record) {
			continue
		}
		if len(record) < 0x18 {
			continue
		}
		flags := binary.LittleEndian.Uint16(record[0x16:0x18])
		if flags&0x01 == 0 {
			continue // 未使用エントリ
		}
		isDir := flags&0x02 != 0
		if dirsOnly && !isDir {
			continue // ファイルのみ対象時にディレクトリをスキップ
		}
		if !dirsOnly && isDir {
			continue // ディレクトリのみ対象時にファイルをスキップ
		}

		if fname := getFileNameIfParent(record, parentInode); fname != "" {
			if wildcardMatch(pattern, fname) {
				found = append(found, MatchEntry{Name: fname, Inode: i})
			}
		}
	}
	return found
}

// wildcardMatch はシェル風ワイルドカードマッチを行う (* = 任意列, ? = 任意1文字)。
// 大文字小文字を無視する。
func wildcardMatch(pattern, name string) bool {
	p := []rune(strings.ToLower(pattern))
	n := []rune(strings.ToLower(name))
	return wildcardMatchInner(p, n)
}

func wildcardMatchInner(p, n []rune) bool {
	if len(p) == 0 {
		return len(n) == 0
	}
	switch p[0] {
	case '*':
		// 0文字以上にマッチ
		return wildcardMatchInner(p[1:], n) ||
			(len(n) > 0 && wildcardMatchInner(p, n[1:]))
	case '?':
		return len(n) > 0 && wildcardMatchInner(p[1:], n[1:])
	default:
		return len(n) > 0 && p[0] == n[0] && wildcardMatchInner(p[1:], n[1:])
	}
}

// getFileNameIfParent は $FILE_NAME 属性 (0x30) を走査し、
// 親 inode が一致する場合に Win32優先のファイル名を返す。
// 一致しない場合は空文字列を返す。
func getFileNameIfParent(record []byte, parentInode uint64) string {
	if len(record) < 0x18 {
		return ""
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	type candidate struct {
		ns   uint8
		name string
	}
	var best *candidate

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}

		if attrType == 0x30 {
			if pos+0x16 > len(record) {
				pos += attrLen
				continue
			}
			contentOffset := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
			cs := pos + contentOffset

			if cs+0x42 > len(record) {
				pos += attrLen
				continue
			}

			parRef := binary.LittleEndian.Uint64(record[cs : cs+8])
			par := parRef & 0x0000FFFFFFFFFFFF

			if par != parentInode {
				pos += attrLen
				continue
			}

			nameLen := int(record[cs+0x40])
			ns := record[cs+0x41] // 0=POSIX 1=Win32 2=DOS 3=Win32&DOS
			nameStart := cs + 0x42
			nameEnd := nameStart + nameLen*2
			if nameEnd > len(record) {
				pos += attrLen
				continue
			}

			utf16 := make([]uint16, nameLen)
			for i := range utf16 {
				utf16[i] = binary.LittleEndian.Uint16(record[nameStart+i*2:])
			}
			fname := windows.UTF16ToString(utf16)

			rank := func(n uint8) int {
				if n == 1 || n == 3 {
					return 2
				} else if n == 2 {
					return 1
				}
				return 0
			}
			if best == nil || rank(ns) > rank(best.ns) {
				best = &candidate{ns: ns, name: fname}
			}
		}
		pos += attrLen
	}
	if best == nil {
		return ""
	}
	return best.name
}

// ── MFTセッション (キャッシュ付き) ────────────────────────────────────────────

// FileEntry はMFT走査で得た1ファイルの情報。
type FileEntry struct {
	RelPath string // ボリューム相対パス (例: "Windows\System32\config\SYSTEM")
	Inode   uint64
}

// Session はMFTを1回だけ読み込んでキャッシュし、複数ファイルの収集を高速化する。
type Session struct {
	Label      string
	handle     *VolumeHandle
	mftData    []byte
	recordSize uint64
}

// NewSession はボリュームを開き、MFTを1回だけ読み込んでSessionを返す。
func NewSession(volume string) (*Session, error) {
	handle, err := Open(volume)
	if err != nil {
		return nil, fmt.Errorf("ボリュームオープン失敗: %w", err)
	}
	mftData, err := handle.ReadMFT()
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("MFT読み込み失敗: %w", err)
	}
	return &Session{
		Label:      volume,
		handle:     handle,
		mftData:    mftData,
		recordSize: handle.BytesPerFileRecord(),
	}, nil
}

// Close はセッションを閉じる。
func (s *Session) Close() {
	s.handle.Close()
}

// ListDirEntries はdirRelPath配下のFileEntry一覧をMFTから取得する。
// recursive=true の場合はサブディレクトリも再帰列挙する。
// ファイル名はMFTから取得するため%4等の特殊文字も正確に扱える。
func (s *Session) ListDirEntries(dirRelPath string, recursive bool) ([]FileEntry, error) {
	var dirInode uint64
	if dirRelPath == "" {
		dirInode = 5
	} else {
		var err error
		dirInode, err = findInodeByPath(s.mftData, dirRelPath, s.recordSize)
		if err != nil {
			return nil, fmt.Errorf("ディレクトリinode解決失敗 (%s): %w", dirRelPath, err)
		}
	}
	var results []FileEntry
	s.listEntriesRecursive(dirInode, dirRelPath, recursive, &results)
	return results, nil
}

func (s *Session) listEntriesRecursive(dirInode uint64, dirRelPath string, recursive bool, out *[]FileEntry) {
	total := uint64(len(s.mftData)) / s.recordSize
	for i := uint64(0); i < total; i++ {
		start := i * s.recordSize
		end := start + s.recordSize
		if end > uint64(len(s.mftData)) {
			break
		}
		record := s.mftData[start:end]
		if !isValidFileRecord(record) || len(record) < 0x30 {
			continue
		}
		flags := binary.LittleEndian.Uint16(record[0x16:0x18])
		if flags&0x01 == 0 {
			continue
		}
		fname := getFileNameIfParent(record, dirInode)
		if fname == "" {
			continue
		}
		actualInode := uint64(binary.LittleEndian.Uint32(record[0x2C:0x30]))
		isDir := flags&0x02 != 0
		relPath := joinSessionPath(dirRelPath, fname)
		if isDir {
			if recursive {
				s.listEntriesRecursive(actualInode, relPath, true, out)
			}
		} else {
			*out = append(*out, FileEntry{RelPath: relPath, Inode: actualInode})
		}
	}
}

// ListUserDirs はUsersディレクトリ直下のサブディレクトリ名とinodeを返す。
func (s *Session) ListUserDirs(usersRelPath string) ([]FileEntry, error) {
	var dirInode uint64
	if usersRelPath == "" {
		dirInode = 5
	} else {
		var err error
		dirInode, err = findInodeByPath(s.mftData, usersRelPath, s.recordSize)
		if err != nil {
			return nil, fmt.Errorf("Usersディレクトリ解決失敗: %w", err)
		}
	}
	total := uint64(len(s.mftData)) / s.recordSize
	var dirs []FileEntry
	for i := uint64(0); i < total; i++ {
		start := i * s.recordSize
		end := start + s.recordSize
		if end > uint64(len(s.mftData)) {
			break
		}
		record := s.mftData[start:end]
		if !isValidFileRecord(record) || len(record) < 0x30 {
			continue
		}
		flags := binary.LittleEndian.Uint16(record[0x16:0x18])
		if flags&0x01 == 0 || flags&0x02 == 0 {
			continue
		}
		fname := getFileNameIfParent(record, dirInode)
		if fname == "" {
			continue
		}
		actualInode := uint64(binary.LittleEndian.Uint32(record[0x2C:0x30]))
		dirs = append(dirs, FileEntry{RelPath: fname, Inode: actualInode})
	}
	return dirs, nil
}

// ReadFileByInode はinode番号からファイルデータを読み取る (MFTキャッシュ利用)。
func (s *Session) ReadFileByInode(inode uint64) ([]byte, error) {
	record := getRecordByInode(s.mftData, inode, s.recordSize)
	if record == nil {
		return nil, fmt.Errorf("inode %d のレコードがMFT内に見つかりません", inode)
	}
	return s.readFileDataWithAttrList(record)
}

// readFileDataWithAttrList は $ATTRIBUTE_LIST を考慮してファイルデータを読む。
func (s *Session) readFileDataWithAttrList(record []byte) ([]byte, error) {
	runs, realSize, err := s.collectDataRuns(record)
	if err != nil {
		return nil, err
	}
	if len(runs) > 0 {
		var out []byte
		for _, run := range runs {
			offset := run.LCN * s.handle.bytesPerCluster
			length := run.Clusters * s.handle.bytesPerCluster
			chunk, err := s.handle.readRaw(offset, length)
			if err != nil {
				return nil, err
			}
			out = append(out, chunk...)
			if realSize > 0 && uint64(len(out)) >= realSize {
				break
			}
		}
		if realSize > 0 && uint64(len(out)) > realSize {
			out = out[:realSize]
		}
		return out, nil
	}
	// 常駐データ
	return getResidentData(record)
}

// GetFileSizeByInode はinode番号のファイルの論理サイズ($DATAサイズ)をバイト単位で返す。
// テンプレートevtx等のデータなしファイルの判別に使用する。
func (s *Session) GetFileSizeByInode(inode uint64) (uint64, error) {
	record, err := s.findRecordByInode(inode)
	if err != nil {
		return 0, err
	}
	return getDataSize(record), nil
}

// findRecordByInode は実inode番号に対応するMFTレコードを返す。
func (s *Session) findRecordByInode(inode uint64) ([]byte, error) {
	// 高速パス
	recStart := inode * s.recordSize
	recEnd := recStart + s.recordSize
	if recEnd <= uint64(len(s.mftData)) {
		record := s.mftData[recStart:recEnd]
		if isValidFileRecord(record) && len(record) >= 0x30 {
			if uint64(binary.LittleEndian.Uint32(record[0x2C:0x30])) == inode {
				return record, nil
			}
		}
	}
	// 線形スキャン
	total := uint64(len(s.mftData)) / s.recordSize
	for i := uint64(0); i < total; i++ {
		start := i * s.recordSize
		end := start + s.recordSize
		if end > uint64(len(s.mftData)) {
			break
		}
		record := s.mftData[start:end]
		if !isValidFileRecord(record) || len(record) < 0x30 {
			continue
		}
		if uint64(binary.LittleEndian.Uint32(record[0x2C:0x30])) == inode {
			return record, nil
		}
	}
	return nil, fmt.Errorf("inode %d が見つかりません", inode)
}

// getDataSize は MFTレコードから $DATA 属性の論理サイズを返す。
// 常駐データの場合はコンテンツ長、非常駐の場合は Real Size フィールドを返す。
func getDataSize(record []byte) uint64 {
	if len(record) < 0x18 {
		return 0
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset
	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x80 { // $DATA
			nonResident := record[pos+8]
			if nonResident == 0 {
				// 常駐: +0x10=コンテンツ長(4B)
				if pos+0x14 <= len(record) {
					return uint64(binary.LittleEndian.Uint32(record[pos+0x10 : pos+0x14]))
				}
			} else {
				// 非常駐: +0x30=Real Size(8B)
				if pos+0x38 <= len(record) {
					return binary.LittleEndian.Uint64(record[pos+0x30 : pos+0x38])
				}
			}
		}
		pos += attrLen
	}
	return 0
}

// ReadFileByRelPath はパスからinodesを解決してデータを読み取る (MFTキャッシュ利用)。
func (s *Session) ReadFileByRelPath(relPath string) ([]byte, error) {
	if strings.EqualFold(relPath, "$MFT") {
		return s.mftData, nil
	}
	inode, err := findInodeByPath(s.mftData, relPath, s.recordSize)
	if err != nil {
		return nil, err
	}
	record := getRecordByInode(s.mftData, inode, s.recordSize)
	if record == nil {
		return nil, fmt.Errorf("inode %d のレコードが見つかりません (path=%s)", inode, relPath)
	}
	return s.readFileDataWithAttrList(record)
}

// FileTimestamps はMFTレコードから取得したファイル時刻。
type FileTimestamps struct {
	Created  time.Time
	Modified time.Time // 最終更新時刻 ($STANDARD_INFORMATION の mTime)
	Accessed time.Time
	Changed  time.Time // MFT変更時刻 (cTime)
}

// GetFileTimestampsByInode は inode の $STANDARD_INFORMATION から時刻を返す。
// NTFS時刻は 1601-01-01 UTC からの100ナノ秒単位。
func (s *Session) GetFileTimestampsByInode(inode uint64) (FileTimestamps, bool) {
	record := getRecordByInode(s.mftData, inode, s.recordSize)
	if record == nil {
		return FileTimestamps{}, false
	}
	return extractTimestamps(record)
}

// extractTimestamps は MFTレコードの $STANDARD_INFORMATION (0x10) から時刻を読む。
// $STANDARD_INFORMATION の構造:
//
//	+0x00: Created (8B)
//	+0x08: Modified (8B)
//	+0x10: MFT Changed (8B)
//	+0x18: Accessed (8B)
//
// 時刻は Windows FILETIME (100ns単位, 1601-01-01 UTC 起点)
func extractTimestamps(record []byte) (FileTimestamps, bool) {
	if len(record) < 0x18 {
		return FileTimestamps{}, false
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset
	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x10 { // $STANDARD_INFORMATION
			nonRes := record[pos+8]
			if nonRes != 0 {
				break // $SI は常に常駐
			}
			contOff := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
			cs := pos + contOff
			if cs+0x20 > len(record) {
				break
			}
			return FileTimestamps{
				Created:  filetimeToTime(binary.LittleEndian.Uint64(record[cs+0x00 : cs+0x08])),
				Modified: filetimeToTime(binary.LittleEndian.Uint64(record[cs+0x08 : cs+0x10])),
				Changed:  filetimeToTime(binary.LittleEndian.Uint64(record[cs+0x10 : cs+0x18])),
				Accessed: filetimeToTime(binary.LittleEndian.Uint64(record[cs+0x18 : cs+0x20])),
			}, true
		}
		pos += attrLen
	}
	return FileTimestamps{}, false
}

// filetimeToTime は Windows FILETIME (100ns, 1601-01-01 UTC) を time.Time に変換する。
func filetimeToTime(ft uint64) time.Time {
	// Windows FILETIME epoch: 1601-01-01 00:00:00 UTC
	// Unix epoch:             1970-01-01 00:00:00 UTC
	// 差分: 11644473600 秒
	const epochDiff = 11644473600
	sec := int64(ft/10000000) - epochDiff
	nsec := int64((ft % 10000000) * 100)
	return time.Unix(sec, nsec).UTC()
}

// FindFileInode はパスからinode番号を返す。存在チェックに使用。
func (s *Session) FindFileInode(relPath string) (uint64, bool) {
	inode, err := findInodeByPath(s.mftData, relPath, s.recordSize)
	if err != nil {
		return 0, false
	}
	return inode, true
}

func joinSessionPath(base, name string) string {
	if base == "" {
		return name
	}
	return base + `\` + name
}
