package main

import (
	"bytes"
	"io"
	"errors"
	"archive/zip"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"path/filepath"
	"runtime/debug"
	"encoding/json"
	"crypto/sha1"

	"github.com/fullsailor/pkcs7"
)

var crtLocation string = "./my.crt"
var keyLocation string = "./my.key"
var archiveName string = "./szip.szp"

func main() {
	var mode, hash, destination, source string
	flag.StringVar(&mode, "mode", "z", "application mode: Zip, eXtract, Info")
	flag.StringVar(&hash, "hash", "UNDEF",  "hash")
	flag.StringVar(&destination, "d", "./unszipped/", "destination to extract to")
	flag.StringVar(&source, "s", ".", "source of the archive")
	flag.Parse()

	switch mode {
	case "z":
		err := PrepareSzp(source)
		if err != nil {
			fmt.Printf("Error occured: %s\nReason is here:\n%s", err, debug.Stack())
			return
		}
		fmt.Println("Your archive has been successfully szipped")

	case "i":
		fmt.Println("Information on the archive:")
		err := GetInfo(hash)
		if err != nil {
			fmt.Printf("Error occured: %s\nReason is here:\n%s", err, debug.Stack())
			return
		}

	case "x":
		err := Extract(destination, hash)
		if err != nil {
			fmt.Printf("Error occured: %s\nReason is here:\n%s", err, debug.Stack())
			return
		}
		fmt.Println(filepath.Join("Your files have been successfully extracted to folder ", destination))

	default:
		fmt.Println("Unknown command. Please read manual and restart the application")
	}
}
//------------------------------------------------------------------------------------

func SignData(data []byte) (signed []byte, err error) {
	var signedData *pkcs7.SignedData
	if signedData, err = pkcs7.NewSignedData(data); err != nil {
		return
	}
	cert, err := tls.LoadX509KeyPair(crtLocation, keyLocation)
	if err != nil {
		return
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("Unable to load a certificate")
	}
	rsaKey := cert.PrivateKey
	var rsaCert *x509.Certificate
	if rsaCert, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return
	}
	if err = signedData.AddSigner(rsaCert, rsaKey, pkcs7.SignerInfoConfig{}); err != nil {
		return
	}
	return signedData.Finish()
}
//------------------------------------------------------------------------------------

func PrepareSzp(source string) (err error) {
	var js, metaZip, zipData []byte
	collector := NewFileCollector()
	if err = collector.WalkFiles(source); err != nil {
		return err
	}

	if js, err = json.Marshal(collector.MetaData); err != nil {
		return err
	}

	metaCollector := NewFileCollector()
	if err = metaCollector.PackFile("meta.json", bytes.NewReader(js)); err != nil {
		return err
	}

	if metaZip, err = metaCollector.ZipData(); err != nil {
		return err
	}

	if zipData, err = collector.ZipData(); err != nil {
		return err
	}

	return MakeSzp(metaZip, zipData)
}

func MakeSzp(metaZip, dataZip []byte) (err error) {
	resultBuf := new(bytes.Buffer)

	if err = binary.Write(resultBuf, binary.LittleEndian, uint32(len(metaZip))); err != nil {
		return
	}

	if _, err = resultBuf.Write(metaZip); err != nil {
		return
	}

	if _, err = resultBuf.Write(dataZip); err != nil {
		return
	}

	var signedData []byte
	if signedData, err = SignData(resultBuf.Bytes()); err != nil {
		return
	}

	if err = ioutil.WriteFile(archiveName, signedData, 0644); err != nil {
		return
	}
	return
}
//------------------------------------------------------------------------------------

//Единица передачи метаданных файла
type FileMeta struct {
	Name string `json:"filename"`
	Original_size uint64 `json:"original_size"`
	Compressed_size uint64 `json:"compressed_size"`
	Mod_time string `json:"mod_time"`
	Sha1_hash [20]byte `json:"sha1_hash"`
}
//------------------------------------------------------------------------------------

//Для сбора итогового файла
type FileCollector struct {
	ZipBuf *bytes.Buffer
	Zip *zip.Writer
	MetaData []*FileMeta
}
//------------------------------------------------------------------------------------

//Конструктор по умолчанию
func NewFileCollector() *FileCollector {
	buf := new(bytes.Buffer)

	return &FileCollector{
		ZipBuf: buf,
		Zip: zip.NewWriter(buf),
		MetaData: make([]*FileMeta, 0, 100),
	}
}
//------------------------------------------------------------------------------------

func (f *FileCollector) WalkFiles(path string) (err error) {
	var files []os.FileInfo
	var fileReader *os.File

	if files, err = ioutil.ReadDir(path); err != nil {
		return err
	}

	for _, file := range files {
		fullPath := filepath.Join(path, "/", file.Name())

		if file.IsDir() {
			if err = f.WalkFiles(fullPath); err != nil {
				return err
			}

		} else {
			header, err := zip.FileInfoHeader(file)
			if err != nil {
				fmt.Println("Couldn't get file's header")
				return err
			}

			fileBytes, err := ioutil.ReadFile(fullPath)
			if err != nil {
				fmt.Println("Unable to obtain bytes from a file")
				return err
			}

			f.AddMeta(header, fullPath, fileBytes)
			if fileReader, err = os.Open(fullPath); err != nil {
				return err
			}

			if err = f.PackFile(fullPath, fileReader); err != nil {
				return err
			}
		}
	}
	return err
}
//------------------------------------------------------------------------------------

func (f *FileCollector) AddMeta(header *zip.FileHeader, fullPath string, fileBytes []byte) {
	f.MetaData = append(f.MetaData, &FileMeta {
		Name: fullPath,
		Original_size: header.UncompressedSize64,
		Compressed_size: header.CompressedSize64,
		Mod_time: header.Modified.Format("Mon Jan 2 15:04:05 MST 2006"),
		Sha1_hash: sha1.Sum(fileBytes) })
	return
}
//------------------------------------------------------------------------------------

func (f *FileCollector) PackFile(filename string, fileReader io.Reader) (err error) {
	var fileWriter io.Writer
	if fileWriter, err = f.Zip.Create(filename); err != nil {
		return err
	}

	if _, err = io.Copy(fileWriter, fileReader); err != nil {
		return err
	}
	return nil
}
//------------------------------------------------------------------------------------

func (f *FileCollector) ZipData() (data []byte, err error) {
	if err = f.Zip.Close(); err != nil {
		return
	}

	data = f.ZipBuf.Bytes()
	return
}
//------------------------------------------------------------------------------------

func CheckSzp(szpLocation string, hash string) (*pkcs7.PKCS7, error) {
	szp, err := ioutil.ReadFile(szpLocation)
	if err != nil {
		return nil, err
	}

	sign, err := pkcs7.Parse(szp)
	if err != nil {
		return nil, err
	}

	err = sign.Verify()
	if err != nil {
		return nil, err
	}

	signer := sign.GetOnlySigner()
	if signer == nil {
		return nil, errors.New("Unable to obtain a single signer")
	}

	if strings.ToUpper(hash) != "UNDEF" {
		hash2 := strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw)))
		if strings.ToUpper(hash) != hash2 {
			fmt.Printf(hash2)
			return nil, errors.New("Certificate hash is corrupted")
		}
	}

	crt, err := tls.LoadX509KeyPair(crtLocation, keyLocation)
	if err != nil {
		return nil, err
	}

	parsedCrt, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return nil, err
	}

	if bytes.Compare(parsedCrt.Raw, signer.Raw) != 0 {
		return nil, errors.New("Certificates don't match")
	}
	return sign, nil
}
//------------------------------------------------------------------------------------

func GetMeta(p *pkcs7.PKCS7) ([]FileMeta, error) {
	//Read meta
	metaSize := int32(binary.LittleEndian.Uint32(p.Content[:4]))
	bytedMeta := bytes.NewReader(p.Content[4 : metaSize + 4])

	readableMeta, err := zip.NewReader(bytedMeta, bytedMeta.Size())
	if err != nil {
		return nil, err
	}

	if (len(readableMeta.File) < 1) {
		return nil, errors.New("File doesn't have meta")
	}

	metaCompressed := readableMeta.File[0] //meta.json

	metaUncompressed, err := metaCompressed.Open()
	if err != nil {
		return nil, err
	}

	var fileMetas []FileMeta
	metaUncompressedBody, err := ioutil.ReadAll(metaUncompressed)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(metaUncompressedBody, &fileMetas)
	if err != nil {
		return nil, err
	}

	return fileMetas, err
}
//------------------------------------------------------------------------------------

func GetInfo(hash string) error {
	sign, err := CheckSzp(archiveName, hash)
	if err != nil {
		return err
	}

	fileMetas, err := GetMeta(sign)
	if err != nil {
		return err
	}

	for _, file := range fileMetas {
		fmt.Println(file)
	}

	return nil
}
//------------------------------------------------------------------------------------

func Extract(destination string, hash string) error {
	sign, err := CheckSzp(archiveName, hash)
	if err != nil {
		return err
	}

	fileMetas, err := GetMeta(sign)
	if err != nil {
		return err
	}

	metaSize := int32(binary.LittleEndian.Uint32(sign.Content[:4]))

	archivedFiles := bytes.NewReader(sign.Content[4 + metaSize:])

	err = UnarchiveFiles(archivedFiles, fileMetas, destination)
	if err != nil {
		return err
	}
	return nil
}
//------------------------------------------------------------------------------------

func UnarchiveFiles(archive *bytes.Reader, fileMetas []FileMeta, destination string) error{
	zipReader, err := zip.NewReader(archive, archive.Size()) 
	if err != nil {
		return err
	}

	// Creating folder to extract to
	if err = os.MkdirAll(destination, 077); err != nil {
		fmt.Println("Couldn't create a folder to extract to")
		return err
	}

	for _, file := range zipReader.File {
		fileInfo := file.FileInfo()
		dirName, _ := filepath.Split(fileInfo.Name())

		if dirName != "" {
			if err = os.MkdirAll(filepath.Join(destination, "/", dirName), 077); err != nil {
				fmt.Println("Couldn't extract a folder")
				return err
			}
		} 

		accessFile, err := file.Open() // gives io.ReadCloser
		if err != nil {
			fmt.Println("Unable to access a file")
			return err
		}

		fileGuts, err := ioutil.ReadAll(accessFile) // read file's bytes to buffer
		if err != nil {
			fmt.Println("Unable to read a file")
			return err
		}

		// Verifying hash for each file
		for _, metaData := range fileMetas{
			if metaData.Name == fileInfo.Name() {
				if metaData.Sha1_hash != sha1.Sum(fileGuts) {
					return errors.New(filepath.Join(file.Name, "'s hash is corrupted. The archive can't be fully unszipped"))
				}
			}
		}

		if err = ioutil.WriteFile(filepath.Join(destination, "/", fileInfo.Name()), fileGuts, 077); err != nil {
			return err
		}
	}

	return nil
}