// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package controllers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const encryptedPOSTSpoolChunkSize = 64 * 1024

type encryptedPOSTSpool struct {
	file      *os.File
	fileName  string
	aead      cipher.AEAD
	nonceBase [4]byte
	chunk     uint64
	plaintext []byte
	closed    bool
}

func spoolEncryptedPOSTObject(source io.Reader) (*encryptedPOSTSpool, int64, error) {
	file, err := os.CreateTemp("", "versitygw-encrypted-post-*")
	if err != nil {
		return nil, 0, err
	}
	fileName := file.Name()
	// POSIX keeps the open descriptor valid after unlinking. This eliminates
	// crash remnants where supported; other platforms retain only ciphertext
	// until Close removes the named file.
	_ = os.Remove(fileName)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		_ = file.Close()
		_ = os.Remove(fileName)
		return nil, 0, fmt.Errorf("generate POST spool key: %w", err)
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		_ = file.Close()
		_ = os.Remove(fileName)
		return nil, 0, fmt.Errorf("initialize POST spool cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		_ = file.Close()
		_ = os.Remove(fileName)
		return nil, 0, fmt.Errorf("initialize POST spool AEAD: %w", err)
	}
	spool := &encryptedPOSTSpool{file: file, fileName: fileName, aead: aead}
	if _, err := rand.Read(spool.nonceBase[:]); err != nil {
		_ = spool.Close()
		return nil, 0, fmt.Errorf("generate POST spool nonce: %w", err)
	}

	buffer := make([]byte, encryptedPOSTSpoolChunkSize)
	var size int64
	var chunk uint64
	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			if err := writeEncryptedPOSTSpoolChunk(file, aead, spool.nonceBase, chunk, buffer[:read]); err != nil {
				clear(buffer)
				_ = spool.Close()
				return nil, 0, err
			}
			size += int64(read)
			chunk++
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			clear(buffer)
			_ = spool.Close()
			return nil, 0, readErr
		}
		if read == 0 {
			continue
		}
	}
	clear(buffer)
	if err := file.Sync(); err != nil {
		_ = spool.Close()
		return nil, 0, fmt.Errorf("sync encrypted POST spool: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = spool.Close()
		return nil, 0, fmt.Errorf("rewind encrypted POST spool: %w", err)
	}
	return spool, size, nil
}

func writeEncryptedPOSTSpoolChunk(destination io.Writer, aead cipher.AEAD, nonceBase [4]byte, chunk uint64, plaintext []byte) error {
	nonce := encryptedPOSTSpoolNonce(nonceBase, chunk)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(plaintext)))
	if _, err := destination.Write(length[:]); err != nil {
		return fmt.Errorf("write encrypted POST spool length: %w", err)
	}
	if _, err := destination.Write(ciphertext); err != nil {
		return fmt.Errorf("write encrypted POST spool chunk: %w", err)
	}
	return nil
}

func encryptedPOSTSpoolNonce(base [4]byte, chunk uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, base[:])
	binary.BigEndian.PutUint64(nonce[4:], chunk)
	return nonce
}

func (spool *encryptedPOSTSpool) Read(destination []byte) (int, error) {
	if spool == nil || spool.closed {
		return 0, os.ErrClosed
	}
	if len(destination) == 0 {
		return 0, nil
	}
	if len(spool.plaintext) == 0 {
		var length [4]byte
		if _, err := io.ReadFull(spool.file, length[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, fmt.Errorf("read encrypted POST spool length: %w", err)
		}
		plaintextLength := binary.BigEndian.Uint32(length[:])
		if plaintextLength == 0 || plaintextLength > encryptedPOSTSpoolChunkSize {
			return 0, fmt.Errorf("invalid encrypted POST spool chunk length %d", plaintextLength)
		}
		ciphertext := make([]byte, int(plaintextLength)+spool.aead.Overhead())
		if _, err := io.ReadFull(spool.file, ciphertext); err != nil {
			return 0, fmt.Errorf("read encrypted POST spool chunk: %w", err)
		}
		plaintext, err := spool.aead.Open(nil, encryptedPOSTSpoolNonce(spool.nonceBase, spool.chunk), ciphertext, nil)
		clear(ciphertext)
		if err != nil {
			return 0, fmt.Errorf("authenticate encrypted POST spool chunk: %w", err)
		}
		spool.chunk++
		spool.plaintext = plaintext
	}

	read := copy(destination, spool.plaintext)
	clear(spool.plaintext[:read])
	spool.plaintext = spool.plaintext[read:]
	return read, nil
}

func (spool *encryptedPOSTSpool) Close() error {
	if spool == nil || spool.closed {
		return nil
	}
	spool.closed = true
	clear(spool.plaintext)
	spool.plaintext = nil
	spool.aead = nil
	closeErr := spool.file.Close()
	removeErr := os.Remove(spool.fileName)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(closeErr, removeErr)
}
