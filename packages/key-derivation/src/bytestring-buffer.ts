/*  Typescript reinterpration of node-forge util.ByteBuffer lib */

export const createBuffer = (input: string, encoding = 'raw') => {
  // TODO: deprecate, use new ByteBuffer() instead
  if (input !== undefined && encoding === 'utf8') {
    input = encodeUtf8(input);
  }
  return new ByteStringBuffer(input);
};

export const isArrayBuffer = (x: any): boolean => {
  return typeof ArrayBuffer !== 'undefined' && x instanceof ArrayBuffer;
};

export const isArrayBufferView = (x: any): boolean => {
  return x && isArrayBuffer(x?.buffer) && x.byteLength !== undefined;
};

export const encodeUtf8 = (str: string): string => {
  return unescape(encodeURIComponent(str));
};

export const decodeUtf8 = (str: string): string => {
  return decodeURIComponent(escape(str));
};

const checkBitsParam = (n: number): void => {
  if (!(n === 8 || n === 16 || n === 24 || n === 32)) {
    throw new Error('Only 8, 16, 24, or 32 bits supported: ' + n);
  }
};

const _MAX_CONSTRUCTED_STRING_LENGTH = 4096;

export class ByteStringBuffer {
  // the data in this buffer
  data = '';
  // the pointer for reading from this buffer
  read = 0;
  _constructedStringLength = 0;

  constructor(b?: string | ArrayBuffer | Buffer | ByteStringBuffer | { data: string; read: number }) {
    if (typeof b === 'string') {
      this.data = b;
    } else if (b instanceof ArrayBuffer || b instanceof Buffer) {
      if (typeof Buffer !== 'undefined' && b instanceof Buffer) {
        this.data = b.toString('binary');
      } else {
        // convert native buffer to forge buffer
        // FIXME: support native buffers internally instead
        const arr = new Uint8Array(b as ArrayBuffer);
        try {
          this.data = String.fromCharCode.apply(null, arr);
        } catch (e) {
          for (let i = 0; i < arr.length; ++i) {
            this.putByte(arr[i]);
          }
        }
      }
    } else if (
      b instanceof ByteStringBuffer ||
      (typeof b === 'object' && typeof b.data === 'string' && typeof b.read === 'number')
    ) {
      // copy existing buffer
      this.data = b.data;
      this.read = b.read;
    }
  }

  /* Note: This is an optimization for V8-based browsers. When V8 concatenates
  a string, the strings are only joined logically using a "cons string" or
  "constructed/concatenated string". These containers keep references to one
  another and can result in very large memory usage. For example, if a 2MB
  string is constructed by concatenating 4 bytes together at a time, the
  memory usage will be ~44MB; so ~22x increase. The strings are only joined
  together when an operation requiring their joining takes place, such as
  substr(). This function is called when adding data to this buffer to ensure
  these types of strings are periodically joined to reduce the memory
  footprint. */
  private _optimizeConstructedString(x: number): void {
    this._constructedStringLength += x;
    if (this._constructedStringLength > _MAX_CONSTRUCTED_STRING_LENGTH) {
      // this substr() should cause the constructed string to join
      this.data.substr(0, 1);
      this._constructedStringLength = 0;
    }
  }

  length(): number {
    return this.data.length - this.read;
  }

  isEmpty(): boolean {
    return this.length() <= 0;
  }

  putByte(b: number) {
    return this.putBytes(String.fromCharCode(b));
  }

  fillWithByte(b: number, n: number): ByteStringBuffer {
    let asString = String.fromCharCode(b);
    let d = this.data;
    while (n > 0) {
      if (n & 1) {
        d += asString;
      }
      n >>>= 1;
      if (n > 0) {
        asString += asString;
      }
    }
    this.data = d;
    this._optimizeConstructedString(n);
    return this;
  }

  putBytes(bytes: string): ByteStringBuffer {
    this.data += bytes;
    this._optimizeConstructedString(bytes.length);
    return this;
  }

  putString(str: string): ByteStringBuffer {
    return this.putBytes(encodeUtf8(str));
  }

  putInt16(i: number): ByteStringBuffer {
    return this.putBytes(String.fromCharCode((i >> 8) & 0xff) + String.fromCharCode(i & 0xff));
  }

  uputInt24(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode((i >> 16) & 0xff) + String.fromCharCode((i >> 8) & 0xff) + String.fromCharCode(i & 0xff),
    );
  }

  putInt32(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode((i >> 24) & 0xff) +
        String.fromCharCode((i >> 16) & 0xff) +
        String.fromCharCode((i >> 8) & 0xff) +
        String.fromCharCode(i & 0xff),
    );
  }

  putInt16Le(i: number): ByteStringBuffer {
    return this.putBytes(String.fromCharCode(i & 0xff) + String.fromCharCode((i >> 8) & 0xff));
  }

  putInt24Le(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i & 0xff) + String.fromCharCode((i >> 8) & 0xff) + String.fromCharCode((i >> 16) & 0xff),
    );
  }

  putInt32Le(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i & 0xff) +
        String.fromCharCode((i >> 8) & 0xff) +
        String.fromCharCode((i >> 16) & 0xff) +
        String.fromCharCode((i >> 24) & 0xff),
    );
  }

  /**
   * Puts an n-bit integer in this buffer in big-endian order.
   */
  putInt(i: number, n: number): ByteStringBuffer {
    checkBitsParam(n);
    let bytes = '';
    do {
      n -= 8;
      bytes += String.fromCharCode((i >> n) & 0xff);
    } while (n > 0);
    return this.putBytes(bytes);
  }

  /**
   * Puts a signed n-bit integer in this buffer in big-endian order. Two's
   * complement representation is used.
   */
  putSignedInt(i: number, n: number): ByteStringBuffer {
    // putInt checks n
    if (i < 0) {
      i += 2 << (n - 1);
    }
    return this.putInt(i, n);
  }

  /**
   * Puts the given buffer into this buffer.
   */
  putBuffer(buffer: ByteStringBuffer): ByteStringBuffer {
    return this.putBytes(buffer.getBytes());
  }

  /**
   * Gets a byte from this buffer and advances the read pointer by 1.
   */
  getByte(): number {
    return this.data.charCodeAt(this.read++);
  }

  /**
   * Gets a uint16 from this buffer in big-endian order and advances the read
   * pointer by 2.
   */
  getInt16(): number {
    const rval = (this.data.charCodeAt(this.read) << 8) ^ this.data.charCodeAt(this.read + 1);
    this.read += 2;
    return rval;
  }

  /**
   * Gets a uint24 from this buffer in big-endian order and advances the read
   * pointer by 3.
   */
  getInt24(): number {
    const rval =
      (this.data.charCodeAt(this.read) << 16) ^
      (this.data.charCodeAt(this.read + 1) << 8) ^
      this.data.charCodeAt(this.read + 2);
    this.read += 3;
    return rval;
  }

  /**
   * Gets a uint32 from this buffer in big-endian order and advances the read
   * pointer by 4.
   */
  getInt32(): number {
    const rval =
      (this.data.charCodeAt(this.read) << 24) ^
      (this.data.charCodeAt(this.read + 1) << 16) ^
      (this.data.charCodeAt(this.read + 2) << 8) ^
      this.data.charCodeAt(this.read + 3);
    this.read += 4;
    return rval;
  }

  /**
   * Gets a uint16 from this buffer in little-endian order and advances the read
   * pointer by 2.
   * */
  getInt16Le(): number {
    const rval = this.data.charCodeAt(this.read) ^ (this.data.charCodeAt(this.read + 1) << 8);
    this.read += 2;
    return rval;
  }

  /**
   * Gets a uint24 from this buffer in little-endian order and advances the read
   * pointer by 3.
   */
  getInt24Le(): number {
    const rval =
      this.data.charCodeAt(this.read) ^
      (this.data.charCodeAt(this.read + 1) << 8) ^
      (this.data.charCodeAt(this.read + 2) << 16);
    this.read += 3;
    return rval;
  }

  /**
   * Gets a uint32 from this buffer in little-endian order and advances the read
   * pointer by 4.
   */
  getInt32Le(): number {
    const rval =
      this.data.charCodeAt(this.read) ^
      (this.data.charCodeAt(this.read + 1) << 8) ^
      (this.data.charCodeAt(this.read + 2) << 16) ^
      (this.data.charCodeAt(this.read + 3) << 24);
    this.read += 4;
    return rval;
  }

  /**
   * Gets an n-bit integer from this buffer in big-endian order and advances the
   * read pointer by ceil(n/8).
   */
  getInt(n: number): number {
    checkBitsParam(n);
    let rval = 0;
    do {
      // TODO: Use (rval * 0x100) if adding support for 33 to 53 bits.
      rval = (rval << 8) + this.data.charCodeAt(this.read++);
      n -= 8;
    } while (n > 0);
    return rval;
  }

  /**
   * Gets a signed n-bit integer from this buffer in big-endian order, using
   * two's complement, and advances the read pointer by n/8.
   */
  getSignedInt(n: number) {
    // getInt checks n
    let x = this.getInt(n);
    const max = 2 << (n - 2);
    if (x >= max) {
      x -= max << 1;
    }
    return x;
  }

  /**
   * Reads bytes out as a binary encoded string and clears them from the
   * buffer. Note that the resulting string is binary encoded (in node.js this
   * encoding is referred to as `binary`, it is *not* `utf8`).
   */
  getBytes(count?: number): string {
    let rval: string;
    if (count) {
      // read count bytes
      count = Math.min(this.length(), count);
      rval = this.data.slice(this.read, this.read + count);
      this.read += count;
    } else if (count === 0) {
      rval = '';
    } else {
      // read all bytes, optimize to only copy when needed
      rval = this.read === 0 ? this.data : this.data.slice(this.read);
      this.clear();
    }
    return rval;
  }

  /**
   * Gets a binary encoded string of the bytes from this buffer without
   * modifying the read pointer.
   */
  bytes(count?: number): string {
    return typeof count === 'undefined' ? this.data.slice(this.read) : this.data.slice(this.read, this.read + count);
  }

  /**
   * Gets a byte at the given index without modifying the read pointer.
   */
  at(i: number): number {
    return this.data.charCodeAt(this.read + i);
  }

  /**
   * Puts a byte at the given index without modifying the read pointer.
   */
  setAt(i: number, b: number): ByteStringBuffer {
    this.data = this.data.substr(0, this.read + i) + String.fromCharCode(b) + this.data.substr(this.read + i + 1);
    return this;
  }

  /**
   * Gets the last byte without modifying the read pointer.
   */
  last(): number {
    return this.data.charCodeAt(this.data.length - 1);
  }

  /**
   * Creates a copy of this buffer.
   */
  copy(): ByteStringBuffer {
    const c = createBuffer(this.data);
    c.read = this.read;
    return c;
  }

  /**
   * Compacts this buffer.
   */
  compact(): ByteStringBuffer {
    if (this.read > 0) {
      this.data = this.data.slice(this.read);
      this.read = 0;
    }
    return this;
  }

  /**
   * Clears this buffer.
   */
  clear(): ByteStringBuffer {
    this.data = '';
    this.read = 0;
    return this;
  }

  /**
   * Shortens this buffer by triming bytes off of the end of this buffer.
   */
  truncate(count: number): ByteStringBuffer {
    const len = Math.max(0, this.length() - count);
    this.data = this.data.substr(this.read, len);
    this.read = 0;
    return this;
  }

  /**
   * Converts this buffer to a hexadecimal string.
   */
  toHex(): string {
    let rval = '';
    for (let i = this.read; i < this.data.length; ++i) {
      const b = this.data.charCodeAt(i);
      if (b < 16) {
        rval += '0';
      }
      rval += b.toString(16);
    }
    return rval;
  }

  /**
   * Converts this buffer to a UTF-16 string (standard JavaScript string).
   */
  toString(): string {
    return decodeUtf8(this.bytes());
  }
}
