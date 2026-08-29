// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	DefaultChunkSize = 1024 * 1024
	containerVersion = 1
	maxHeaderSize    = 64 * 1024
	gcmTagSize       = 16
	preambleSize     = 12
)

var containerMagic = [8]byte{'V', 'G', 'W', 'S', 'S', 'E', '1', 0}

type LayerRequest struct {
	Provider KeyProvider
	KeyID    string
	Context  []byte
}

type WriterOptions struct {
	Identity         Identity
	Mode             Mode
	PlaintextSize    int64
	Layers           []LayerRequest
	BucketKeyEnabled bool
}

type containerManifest struct {
	Version          int             `json:"version"`
	Mode             Mode            `json:"mode"`
	PlaintextSize    int64           `json:"plaintext_size"`
	ChunkSize        int             `json:"chunk_size"`
	IdentityHash     []byte          `json:"identity_hash"`
	PayloadAAD       []byte          `json:"payload_aad"`
	Layers           []layerManifest `json:"layers"`
	HeaderMAC        []byte          `json:"header_mac,omitempty"`
	BucketKeyEnabled bool            `json:"bucket_key_enabled,omitempty"`
}

type layerManifest struct {
	WrappedDataKey WrappedDataKey `json:"wrapped_data_key"`
	NoncePrefix    []byte         `json:"nonce_prefix"`
	Context        []byte         `json:"context,omitempty"`
}

type KeyReference struct {
	Provider string
	KeyID    string
}

type ContainerInfo struct {
	FormatVersion    int
	Mode             Mode
	PlaintextSize    int64
	BucketKeyEnabled bool
	KeyReferences    []KeyReference
}

type Writer struct {
	destination    io.Writer
	manifest       containerManifest
	header         []byte
	dataKeys       []SensitiveBytes
	buffer         []byte
	written        int64
	chunkIndex     uint32
	ciphertextSize int64
	closed         bool
	err            error
}

func NewWriter(ctx context.Context, destination io.Writer, opts WriterOptions) (*Writer, error) {
	if destination == nil || !opts.Identity.valid() || opts.PlaintextSize < 0 || len(opts.Layers) == 0 || len(opts.Layers) > 2 {
		return nil, ErrInvalidContainer
	}
	if opts.Mode != ModeSSES3 && opts.Mode != ModeSSEC && opts.Mode != ModeSSEKMS && opts.Mode != ModeDSSEKMS {
		return nil, ErrUnsupportedEncryption
	}
	if opts.Mode == ModeDSSEKMS && len(opts.Layers) != 2 {
		return nil, ErrInvalidContainer
	}
	if opts.Mode != ModeDSSEKMS && len(opts.Layers) != 1 {
		return nil, ErrInvalidContainer
	}

	identityBytes, identityHash, err := marshalIdentity(opts.Identity)
	if err != nil {
		return nil, err
	}
	manifest := containerManifest{
		Version:          containerVersion,
		Mode:             opts.Mode,
		PlaintextSize:    opts.PlaintextSize,
		ChunkSize:        DefaultChunkSize,
		IdentityHash:     identityHash,
		PayloadAAD:       make([]byte, sha256.Size),
		Layers:           make([]layerManifest, 0, len(opts.Layers)),
		BucketKeyEnabled: opts.BucketKeyEnabled,
	}
	if _, err := io.ReadFull(rand.Reader, manifest.PayloadAAD); err != nil {
		return nil, fmt.Errorf("generate payload AAD: %w", err)
	}
	dataKeys := make([]SensitiveBytes, 0, len(opts.Layers))
	cleanup := func() {
		for i := range dataKeys {
			dataKeys[i].Destroy()
		}
	}
	for index, request := range opts.Layers {
		if request.Provider == nil {
			cleanup()
			return nil, ErrInvalidKey
		}
		contextBytes := layerContext(identityBytes, opts.Mode, index, request.Context)
		key, wrapped, err := request.Provider.GenerateDataKey(ctx, KeyRequest{KeyID: request.KeyID, Context: contextBytes, ClientContext: request.Context})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("generate layer %d data key: %w", index, err)
		}
		noncePrefix := make([]byte, 8)
		if _, err := io.ReadFull(rand.Reader, noncePrefix); err != nil {
			key.Destroy()
			cleanup()
			return nil, fmt.Errorf("generate object nonce: %w", err)
		}
		dataKeys = append(dataKeys, key)
		manifest.Layers = append(manifest.Layers, layerManifest{WrappedDataKey: wrapped, NoncePrefix: noncePrefix, Context: append([]byte(nil), request.Context...)})
	}

	core, err := marshalManifestCore(manifest)
	if err != nil {
		cleanup()
		return nil, err
	}
	manifest.HeaderMAC = computeHeaderMAC(dataKeys, core)
	header, err := json.Marshal(manifest)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("marshal encrypted object header: %w", err)
	}
	if len(header) > maxHeaderSize {
		cleanup()
		return nil, ErrInvalidContainer
	}
	preamble := make([]byte, preambleSize)
	copy(preamble, containerMagic[:])
	binary.BigEndian.PutUint32(preamble[len(containerMagic):], uint32(len(header)))
	if _, err := destination.Write(preamble); err != nil {
		cleanup()
		return nil, fmt.Errorf("write encrypted object preamble: %w", err)
	}
	if _, err := destination.Write(header); err != nil {
		cleanup()
		return nil, fmt.Errorf("write encrypted object header: %w", err)
	}

	chunkCount := chunkCount(opts.PlaintextSize, DefaultChunkSize)
	ciphertextSize := int64(preambleSize+len(header)) + opts.PlaintextSize + chunkCount*int64(gcmTagSize*len(opts.Layers))
	return &Writer{
		destination:    destination,
		manifest:       manifest,
		header:         header,
		dataKeys:       dataKeys,
		buffer:         make([]byte, 0, DefaultChunkSize),
		ciphertextSize: ciphertextSize,
	}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("write to closed encrypted object")
	}
	if w.err != nil {
		return 0, w.err
	}
	if int64(len(p)) > w.manifest.PlaintextSize-w.written {
		return 0, fmt.Errorf("%w: plaintext exceeds declared size", ErrInvalidContainer)
	}
	original := len(p)
	for len(p) > 0 {
		space := DefaultChunkSize - len(w.buffer)
		n := min(space, len(p))
		w.buffer = append(w.buffer, p[:n]...)
		w.written += int64(n)
		p = p[n:]
		if len(w.buffer) == DefaultChunkSize {
			if err := w.flushChunk(); err != nil {
				w.err = err
				return original - len(p), err
			}
		}
	}
	return original, nil
}

func (w *Writer) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	defer func() {
		for i := range w.dataKeys {
			w.dataKeys[i].Destroy()
		}
		clear(w.buffer)
	}()
	if w.err != nil {
		return w.err
	}
	if w.written != w.manifest.PlaintextSize {
		return fmt.Errorf("%w: wrote %d of %d plaintext bytes", ErrInvalidContainer, w.written, w.manifest.PlaintextSize)
	}
	if len(w.buffer) != 0 {
		w.err = w.flushChunk()
	}
	return w.err
}

func (w *Writer) CiphertextSize() int64 { return w.ciphertextSize }

func (w *Writer) flushChunk() error {
	payload := append([]byte(nil), w.buffer...)
	for layerIndex, layer := range w.manifest.Layers {
		aead, err := newGCM(w.dataKeys[layerIndex])
		if err != nil {
			return err
		}
		nonce := chunkNonce(layer.NoncePrefix, w.chunkIndex)
		payload = aead.Seal(nil, nonce, payload, chunkAAD(w.manifest.PayloadAAD, w.manifest.IdentityHash, w.chunkIndex, layerIndex))
	}
	if _, err := w.destination.Write(payload); err != nil {
		return fmt.Errorf("write encrypted object chunk: %w", err)
	}
	clear(payload)
	w.buffer = w.buffer[:0]
	w.chunkIndex++
	return nil
}

type Reader struct {
	ctx        context.Context
	source     io.ReaderAt
	manifest   containerManifest
	dataKeys   []SensitiveBytes
	dataOffset int64
	sourceSize int64
	closed     bool
}

func Open(ctx context.Context, source io.ReaderAt, sourceSize int64, identity Identity, providers ProviderMap) (*Reader, error) {
	if !identity.valid() {
		return nil, ErrInvalidContainer
	}
	manifest, headerLength, err := readContainerManifest(source, sourceSize)
	if err != nil {
		return nil, err
	}
	identityBytes, identityHash, err := marshalIdentity(identity)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(identityHash, manifest.IdentityHash) != 1 {
		return nil, ErrIdentityMismatch
	}

	keys := make([]SensitiveBytes, 0, len(manifest.Layers))
	cleanup := func() {
		for i := range keys {
			keys[i].Destroy()
		}
	}
	for index, layer := range manifest.Layers {
		provider := providers[layer.WrappedDataKey.Provider]
		if provider == nil {
			cleanup()
			return nil, ErrKeyNotFound
		}
		key, err := provider.UnwrapKey(ctx, KeyRequest{KeyID: layer.WrappedDataKey.KeyID, Context: layerContext(identityBytes, manifest.Mode, index, layer.Context), ClientContext: layer.Context}, layer.WrappedDataKey)
		if err != nil {
			cleanup()
			if errors.Is(err, ErrAuthentication) {
				return nil, ErrAuthentication
			}
			return nil, fmt.Errorf("unwrap layer %d: %w", index, err)
		}
		keys = append(keys, key)
	}
	core, err := marshalManifestCore(manifest)
	if err != nil {
		cleanup()
		return nil, err
	}
	if subtle.ConstantTimeCompare(computeHeaderMAC(keys, core), manifest.HeaderMAC) != 1 {
		cleanup()
		return nil, ErrAuthentication
	}
	return &Reader{ctx: ctx, source: source, manifest: manifest, dataKeys: keys, dataOffset: int64(preambleSize + headerLength), sourceSize: sourceSize}, nil
}

// Inspect reads and structurally validates only the encrypted-container header.
// It does not unwrap data keys or read ciphertext chunks.
func Inspect(source io.ReaderAt, sourceSize int64) (ContainerInfo, error) {
	manifest, _, err := readContainerManifest(source, sourceSize)
	if err != nil {
		return ContainerInfo{}, err
	}
	info := ContainerInfo{
		FormatVersion: containerVersion, Mode: manifest.Mode, PlaintextSize: manifest.PlaintextSize,
		BucketKeyEnabled: manifest.BucketKeyEnabled,
		KeyReferences:    make([]KeyReference, 0, len(manifest.Layers)),
	}
	for _, layer := range manifest.Layers {
		info.KeyReferences = append(info.KeyReferences, KeyReference{Provider: layer.WrappedDataKey.Provider, KeyID: layer.WrappedDataKey.KeyID})
	}
	return info, nil
}

// Rewrap replaces wrapped data keys with each provider's active key while
// copying the authenticated object ciphertext byte-for-byte. Callers must
// publish destination atomically because an output error may leave it partial.
func Rewrap(ctx context.Context, destination io.Writer, source io.ReaderAt, sourceSize int64, identity Identity, providers ProviderMap) (ContainerInfo, error) {
	if destination == nil || !identity.valid() {
		return ContainerInfo{}, ErrInvalidContainer
	}
	manifest, oldHeaderLength, err := readContainerManifest(source, sourceSize)
	if err != nil {
		return ContainerInfo{}, err
	}
	identityBytes, identityHash, err := marshalIdentity(identity)
	if err != nil {
		return ContainerInfo{}, err
	}
	if subtle.ConstantTimeCompare(identityHash, manifest.IdentityHash) != 1 {
		return ContainerInfo{}, ErrIdentityMismatch
	}

	keys := make([]SensitiveBytes, 0, len(manifest.Layers))
	defer func() {
		for i := range keys {
			keys[i].Destroy()
		}
	}()
	for index := range manifest.Layers {
		layer := &manifest.Layers[index]
		if layer.WrappedDataKey.Provider == customerProviderName {
			return ContainerInfo{}, ErrUnsupportedEncryption
		}
		provider := providers[layer.WrappedDataKey.Provider]
		if provider == nil {
			return ContainerInfo{}, ErrKeyNotFound
		}
		contextBytes := layerContext(identityBytes, manifest.Mode, index, layer.Context)
		key, err := provider.UnwrapKey(ctx, KeyRequest{KeyID: layer.WrappedDataKey.KeyID, Context: contextBytes, ClientContext: layer.Context}, layer.WrappedDataKey)
		if err != nil {
			return ContainerInfo{}, fmt.Errorf("unwrap layer %d: %w", index, err)
		}
		keys = append(keys, key)
	}
	core, err := marshalManifestCore(manifest)
	if err != nil {
		return ContainerInfo{}, err
	}
	if subtle.ConstantTimeCompare(computeHeaderMAC(keys, core), manifest.HeaderMAC) != 1 {
		return ContainerInfo{}, ErrAuthentication
	}

	for index := range manifest.Layers {
		layer := &manifest.Layers[index]
		provider := providers[layer.WrappedDataKey.Provider]
		contextBytes := layerContext(identityBytes, manifest.Mode, index, layer.Context)
		wrapped, err := provider.WrapKey(ctx, KeyRequest{Context: contextBytes, ClientContext: layer.Context}, keys[index])
		if err != nil {
			return ContainerInfo{}, fmt.Errorf("rewrap layer %d: %w", index, err)
		}
		layer.WrappedDataKey = wrapped
	}
	core, err = marshalManifestCore(manifest)
	if err != nil {
		return ContainerInfo{}, err
	}
	manifest.HeaderMAC = computeHeaderMAC(keys, core)
	header, err := json.Marshal(manifest)
	if err != nil || len(header) > maxHeaderSize {
		return ContainerInfo{}, ErrInvalidContainer
	}
	preamble := make([]byte, preambleSize)
	copy(preamble, containerMagic[:])
	binary.BigEndian.PutUint32(preamble[len(containerMagic):], uint32(len(header)))
	if _, err := destination.Write(preamble); err != nil {
		return ContainerInfo{}, fmt.Errorf("write rewrapped object preamble: %w", err)
	}
	if _, err := destination.Write(header); err != nil {
		return ContainerInfo{}, fmt.Errorf("write rewrapped object header: %w", err)
	}
	dataOffset := int64(preambleSize + oldHeaderLength)
	if _, err := io.Copy(destination, io.NewSectionReader(source, dataOffset, sourceSize-dataOffset)); err != nil {
		return ContainerInfo{}, fmt.Errorf("copy rewrapped object ciphertext: %w", err)
	}
	return containerInfo(manifest), nil
}

func containerInfo(manifest containerManifest) ContainerInfo {
	info := ContainerInfo{
		FormatVersion: containerVersion, Mode: manifest.Mode, PlaintextSize: manifest.PlaintextSize,
		BucketKeyEnabled: manifest.BucketKeyEnabled,
		KeyReferences:    make([]KeyReference, 0, len(manifest.Layers)),
	}
	for _, layer := range manifest.Layers {
		info.KeyReferences = append(info.KeyReferences, KeyReference{Provider: layer.WrappedDataKey.Provider, KeyID: layer.WrappedDataKey.KeyID})
	}
	return info
}

func readContainerManifest(source io.ReaderAt, sourceSize int64) (containerManifest, int, error) {
	if source == nil || sourceSize < preambleSize {
		return containerManifest{}, 0, ErrInvalidContainer
	}
	preamble := make([]byte, preambleSize)
	if _, err := source.ReadAt(preamble, 0); err != nil {
		return containerManifest{}, 0, fmt.Errorf("%w: read preamble", ErrInvalidContainer)
	}
	if !bytes.Equal(preamble[:len(containerMagic)], containerMagic[:]) {
		return containerManifest{}, 0, ErrInvalidContainer
	}
	headerLength := int(binary.BigEndian.Uint32(preamble[len(containerMagic):]))
	if headerLength <= 0 || headerLength > maxHeaderSize || int64(preambleSize+headerLength) > sourceSize {
		return containerManifest{}, 0, ErrInvalidContainer
	}
	header := make([]byte, headerLength)
	if _, err := source.ReadAt(header, preambleSize); err != nil {
		return containerManifest{}, 0, fmt.Errorf("%w: read header", ErrInvalidContainer)
	}
	var manifest containerManifest
	decoder := json.NewDecoder(bytes.NewReader(header))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return containerManifest{}, 0, fmt.Errorf("%w: decode header", ErrInvalidContainer)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return containerManifest{}, 0, ErrInvalidContainer
	}
	if manifest.Version != containerVersion || manifest.ChunkSize != DefaultChunkSize || manifest.PlaintextSize < 0 || len(manifest.IdentityHash) != sha256.Size || len(manifest.PayloadAAD) != sha256.Size || len(manifest.Layers) == 0 || len(manifest.Layers) > 2 || len(manifest.HeaderMAC) != sha256.Size {
		return containerManifest{}, 0, ErrInvalidContainer
	}
	if manifest.Mode != ModeSSES3 && manifest.Mode != ModeSSEC && manifest.Mode != ModeSSEKMS && manifest.Mode != ModeDSSEKMS {
		return containerManifest{}, 0, ErrInvalidContainer
	}
	if (manifest.Mode == ModeDSSEKMS) != (len(manifest.Layers) == 2) {
		return containerManifest{}, 0, ErrInvalidContainer
	}
	for _, layer := range manifest.Layers {
		if len(layer.NoncePrefix) != 8 || layer.WrappedDataKey.Provider == "" || layer.WrappedDataKey.KeyID == "" || len(layer.WrappedDataKey.Ciphertext) == 0 {
			return containerManifest{}, 0, ErrInvalidContainer
		}
	}
	expectedSize := int64(preambleSize+headerLength) + manifest.PlaintextSize + chunkCount(manifest.PlaintextSize, manifest.ChunkSize)*int64(gcmTagSize*len(manifest.Layers))
	if sourceSize != expectedSize {
		return containerManifest{}, 0, ErrInvalidContainer
	}
	return manifest, headerLength, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrInvalidContainer
}

func (r *Reader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	for i := range r.dataKeys {
		r.dataKeys[i].Destroy()
	}
	r.dataKeys = nil
	return nil
}

func (r *Reader) PlaintextSize() int64 { return r.manifest.PlaintextSize }
func (r *Reader) Mode() Mode           { return r.manifest.Mode }

func (r *Reader) Result() Result {
	result := Result{Mode: r.manifest.Mode, BucketKeyEnabled: r.manifest.BucketKeyEnabled}
	if len(r.manifest.Layers) == 0 {
		return result
	}
	switch r.manifest.Mode {
	case ModeSSEKMS, ModeDSSEKMS:
		result.KMSKeyID = r.manifest.Layers[0].WrappedDataKey.KeyID
	case ModeSSEC:
		result.CustomerKeyMD5 = r.manifest.Layers[0].WrappedDataKey.KeyID
	}
	return result
}

func IsContainer(source io.ReaderAt) (bool, error) {
	if source == nil {
		return false, ErrInvalidContainer
	}
	magic := make([]byte, len(containerMagic))
	if _, err := source.ReadAt(magic, 0); err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, err
	}
	return bytes.Equal(magic, containerMagic[:]), nil
}

func (r *Reader) ReadRange(start, length int64) ([]byte, error) {
	stream, err := r.RangeReader(start, length)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	return io.ReadAll(stream)
}

func (r *Reader) RangeReader(start, length int64) (io.ReadCloser, error) {
	if r.closed || start < 0 || length < 0 || start > r.manifest.PlaintextSize || length > r.manifest.PlaintextSize-start {
		return nil, ErrInvalidContainer
	}
	return &rangeReader{container: r, position: start, end: start + length}, nil
}

type rangeReader struct {
	container *Reader
	position  int64
	end       int64
	chunk     []byte
	chunkBase int64
	closed    bool
}

func (r *rangeReader) Read(destination []byte) (int, error) {
	if r.closed || r.position >= r.end {
		return 0, io.EOF
	}
	if len(destination) == 0 {
		return 0, nil
	}
	select {
	case <-r.container.ctx.Done():
		return 0, r.container.ctx.Err()
	default:
	}
	chunkIndex := r.position / int64(r.container.manifest.ChunkSize)
	if r.chunk == nil || r.chunkBase != chunkIndex*int64(r.container.manifest.ChunkSize) {
		clear(r.chunk)
		plain, err := r.container.readChunk(uint32(chunkIndex))
		if err != nil {
			return 0, err
		}
		r.chunk = plain
		r.chunkBase = chunkIndex * int64(r.container.manifest.ChunkSize)
	}
	from := r.position - r.chunkBase
	available := min(int64(len(r.chunk))-from, r.end-r.position)
	n := copy(destination, r.chunk[from:from+min(available, int64(len(destination)))])
	r.position += int64(n)
	if r.position >= r.chunkBase+int64(len(r.chunk)) {
		clear(r.chunk)
		r.chunk = nil
	}
	return n, nil
}

func (r *rangeReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	clear(r.chunk)
	r.chunk = nil
	return r.container.Close()
}

func (r *Reader) readChunk(index uint32) ([]byte, error) {
	if r.closed || len(r.dataKeys) != len(r.manifest.Layers) {
		return nil, ErrInvalidContainer
	}
	plainStart := int64(index) * int64(r.manifest.ChunkSize)
	if plainStart >= r.manifest.PlaintextSize {
		return nil, ErrInvalidContainer
	}
	plainLength := min(int64(r.manifest.ChunkSize), r.manifest.PlaintextSize-plainStart)
	cipherChunkSize := int64(r.manifest.ChunkSize + gcmTagSize*len(r.manifest.Layers))
	cipherLength := plainLength + int64(gcmTagSize*len(r.manifest.Layers))
	payload := make([]byte, cipherLength)
	if _, err := r.source.ReadAt(payload, r.dataOffset+int64(index)*cipherChunkSize); err != nil {
		return nil, fmt.Errorf("%w: read chunk", ErrInvalidContainer)
	}
	for layerIndex := len(r.manifest.Layers) - 1; layerIndex >= 0; layerIndex-- {
		aead, err := newGCM(r.dataKeys[layerIndex])
		if err != nil {
			return nil, err
		}
		nonce := chunkNonce(r.manifest.Layers[layerIndex].NoncePrefix, index)
		plaintext, err := aead.Open(nil, nonce, payload, chunkAAD(r.manifest.PayloadAAD, r.manifest.IdentityHash, index, layerIndex))
		clear(payload)
		if err != nil {
			return nil, ErrAuthentication
		}
		payload = plaintext
	}
	return payload, nil
}

func marshalIdentity(identity Identity) ([]byte, []byte, error) {
	data, err := json.Marshal(identity)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal object identity: %w", err)
	}
	digest := sha256.Sum256(data)
	return data, digest[:], nil
}

func layerContext(identity []byte, mode Mode, index int, additional []byte) []byte {
	result := make([]byte, 0, len(identity)+len(mode)+len(additional)+16)
	result = append(result, "versitygw/object-key/"...)
	result = append(result, identity...)
	result = append(result, 0)
	result = append(result, mode...)
	result = append(result, byte(index))
	return append(result, additional...)
}

func marshalManifestCore(manifest containerManifest) ([]byte, error) {
	manifest.HeaderMAC = nil
	core, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted object header core: %w", err)
	}
	return core, nil
}

func computeHeaderMAC(keys []SensitiveBytes, core []byte) []byte {
	keySeed := sha256.New()
	for _, key := range keys {
		_, _ = keySeed.Write(key)
	}
	macKey := keySeed.Sum(nil)
	defer clear(macKey)
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(containerMagic[:])
	_, _ = mac.Write(core)
	return mac.Sum(nil)
}

func chunkNonce(prefix []byte, index uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], index)
	return nonce
}

func chunkAAD(payloadAAD, identityHash []byte, index uint32, layer int) []byte {
	aad := make([]byte, 0, len(payloadAAD)+len(identityHash)+8)
	aad = append(aad, payloadAAD...)
	aad = append(aad, identityHash...)
	var suffix [8]byte
	binary.BigEndian.PutUint32(suffix[:4], index)
	binary.BigEndian.PutUint32(suffix[4:], uint32(layer))
	return append(aad, suffix[:]...)
}

func chunkCount(size int64, chunkSize int) int64 {
	if size == 0 {
		return 0
	}
	return (size + int64(chunkSize) - 1) / int64(chunkSize)
}

// MaximumCiphertextSize returns a safe allocation bound before the variable
// container header has been serialized. The actual size is available from
// Writer.CiphertextSize after construction.
func MaximumCiphertextSize(plaintextSize int64, layers int) (int64, error) {
	if plaintextSize < 0 || layers < 1 || layers > 2 {
		return 0, ErrInvalidContainer
	}
	chunks := chunkCount(plaintextSize, DefaultChunkSize)
	overhead := int64(preambleSize+maxHeaderSize) + chunks*int64(gcmTagSize*layers)
	if plaintextSize > int64(^uint64(0)>>1)-overhead {
		return 0, ErrInvalidContainer
	}
	return plaintextSize + overhead, nil
}
