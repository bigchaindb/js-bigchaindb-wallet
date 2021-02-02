/*  Typescript interpration of node-forge asn1 lib */

import { ByteStringBuffer } from './bytestring-buffer';

/**
 * ASN.1 classes.
 */
export enum ASN1Class {
  UNIVERSAL = 0x00,
  APPLICATION = 0x40,
  CONTEXT_SPECIFIC = 0x80,
  PRIVATE = 0xc0,
}

/**
 * ASN.1 types. Not all types are supported by this implementation, only
 * those necessary to implement a simple PKI are implemented.
 */
export enum ASN1Type {
  NONE = 0,
  BOOLEAN = 1,
  INTEGER = 2,
  BITSTRING = 3,
  OCTETSTRING = 4,
  NULL = 5,
  OID = 6,
  ODESC = 7,
  EXTERNAL = 8,
  REAL = 9,
  ENUMERATED = 10,
  EMBEDDED = 11,
  UTF8 = 12,
  ROID = 13,
  SEQUENCE = 16,
  SET = 17,
  PRINTABLESTRING = 19,
  IA5STRING = 22,
  UTCTIME = 23,
  GENERALIZEDTIME = 24,
  BMPSTRING = 30,
}

export type AsnObject = {
  tagClass: ASN1Class;
  type: ASN1Type;
  constructed: boolean;
  composed: boolean;
  value: string | AsnObject | (string | AsnObject)[];
  // bitStringContents?: string | Buffer;
  bitStringContents?: string;
  original?: string | AsnObject | (string | AsnObject)[];
};

export class asn1 {
  static create(
    tagClass: ASN1Class,
    type: ASN1Type,
    constructed: boolean,
    value: string | AsnObject | (string | AsnObject)[],
    options?: { bitStringContents: string },
  ): AsnObject {
    /* An asn1 object has a tagClass, a type, a constructed flag, and a
      value. The value's type depends on the constructed flag. If
      constructed, it will contain a list of other asn1 objects. If not,
      it will contain the ASN.1 value as an array of bytes formatted
      according to the ASN.1 data type. */

    if (value instanceof Array) {
      value = value.filter((val) => val !== undefined);
    }

    const obj: AsnObject = {
      tagClass: tagClass,
      type: type,
      constructed: constructed,
      composed: constructed || value instanceof Array,
      value: value,
    };
    if (options && 'bitStringContents' in options) {
      // TODO: copy byte buffer if it's a buffer not a string
      obj.bitStringContents = options.bitStringContents;
      // TODO: add readonly flag to avoid this overhead
      // save copy to detect changes
      obj.original = asn1.copy(obj);
    }
    return obj;
  }

  static copy(obj: AsnObject, options?: { excludeBitStringContents: boolean }): AsnObject;
  static copy(obj: AsnObject[], options?: { excludeBitStringContents: boolean }): AsnObject[];
  static copy(obj: string, options?: { excludeBitStringContents: boolean }): string;
  static copy(obj: string[], options?: { excludeBitStringContents: boolean }): string[];

  static copy(
    obj: AsnObject | AsnObject[] | string | string[],
    options?: { excludeBitStringContents: boolean },
  ): AsnObject | AsnObject[] | string | string[] {
    if (obj instanceof Array) {
      const copy: AsnObject[] = [];
      for (let i = 0; i < obj.length; ++i) {
        copy.push(asn1.copy(obj[i] as AsnObject, options));
      }
      return copy as AsnObject[];
    }

    if (typeof obj === 'string') {
      // TODO: copy byte buffer if it's a buffer not a string
      return obj;
    }

    const copy: AsnObject = {
      tagClass: obj.tagClass,
      type: obj.type,
      constructed: obj.constructed,
      composed: obj.composed,
      value: asn1.copy(obj.value as string, options),
    };
    if (options && !options.excludeBitStringContents) {
      // TODO: copy byte buffer if it's a buffer not a string
      copy.bitStringContents = obj.bitStringContents;
    }
    return copy as AsnObject;
  }

  static equals(
    obj1: AsnObject | string | (AsnObject | string)[],
    obj2: AsnObject | string | (AsnObject | string)[],
    options?: { includeBitStringContents: boolean },
  ): boolean {
    if (obj1 instanceof Array || obj2 instanceof Array) {
      if (!(obj1 instanceof Array) && obj2 instanceof Array) {
        return false;
      } else if (obj1 instanceof Array && !(obj2 instanceof Array)) {
        return false;
      } else if (obj1 instanceof Array && obj2 instanceof Array) {
        if (obj1.length !== obj2.length) {
          return false;
        }
        for (let i = 0; i < obj1.length; ++i) {
          if (!asn1.equals(obj1[i], obj2[i])) {
            return false;
          }
        }
        return true;
      }
      return false;
    }

    if (typeof obj1 !== typeof obj2) {
      return false;
    }

    if (typeof obj1 === 'string' || typeof obj2 === 'string') {
      return obj1 === obj2;
    }

    let equal =
      obj1.tagClass === obj2.tagClass &&
      obj1.type === obj2.type &&
      obj1.constructed === obj2.constructed &&
      obj1.composed === obj2.composed &&
      asn1.equals(obj1.value, obj2.value);
    if (options && options.includeBitStringContents) {
      equal = equal && obj1.bitStringContents === obj2.bitStringContents;
    }

    return equal;
  }

  static toDer(obj: AsnObject): ByteStringBuffer {
    const bytes = new ByteStringBuffer();
    // build the first byte
    let b1 = obj.tagClass | obj.type;
    // for storing the ASN.1 value
    const value = new ByteStringBuffer();

    // use BIT STRING contents if available and data not changed
    let useBitStringContents = false;
    if ('bitStringContents' in obj) {
      useBitStringContents = true;
      if (obj.original) {
        useBitStringContents = asn1.equals(obj, obj.original);
      }
    }

    if (useBitStringContents) {
      value.putBytes(obj.bitStringContents);
    } else if (obj.composed) {
      const asnArrayValue = obj.value as (AsnObject | string)[];
      // if composed, use each child asn1 object's DER bytes as value
      // turn on 6th bit (0x20 = 32) to indicate asn1 is constructed
      // from other asn1 objects
      if (obj.constructed) {
        b1 |= 0x20;
      } else {
        // type is a bit string, add unused bits of 0x00
        value.putByte(0x00);
      }

      // add all of the child DER bytes together
      for (let i = 0; i < asnArrayValue.length; ++i) {
        if (asnArrayValue[i] !== undefined) {
          // TODO: fix typing
          value.putBuffer(asn1.toDer(asnArrayValue[i] as AsnObject));
          // value.putBuffer(asn1.toDer(obj.value[i] as any));
        }
      }
    } else {
      // use asn1.value directly
      const asnStringValue = obj.value as string;
      if (obj.type === ASN1Type.BMPSTRING) {
        for (let i = 0; i < asnStringValue.length; ++i) {
          value.putInt16(asnStringValue.charCodeAt(i));
        }
      } else {
        // ensure integer is minimally-encoded
        // TODO: should all leading bytes be stripped vs just one?
        // .. ex '00 00 01' => '01'?
        if (
          obj.type === ASN1Type.INTEGER &&
          asnStringValue.length > 1 &&
          // leading 0x00 for positive integer
          ((asnStringValue.charCodeAt(0) === 0 && (asnStringValue.charCodeAt(1) & 0x80) === 0) ||
            // leading 0xFF for negative integer
            (asnStringValue.charCodeAt(0) === 0xff && (asnStringValue.charCodeAt(1) & 0x80) === 0x80))
        ) {
          value.putBytes(asnStringValue.substr(1));
        } else {
          value.putBytes(asnStringValue);
        }
      }
    }

    // add tag byte
    bytes.putByte(b1);

    // use "short form" encoding
    if (value.length() <= 127) {
      // one byte describes the length
      // bit 8 = 0 and bits 7-1 = length
      bytes.putByte(value.length() & 0x7f);
    } else {
      // use "long form" encoding
      // 2 to 127 bytes describe the length
      // first byte: bit 8 = 1 and bits 7-1 = # of additional bytes
      // other bytes: length in base 256, big-endian
      let len = value.length();
      let lenBytes = '';
      do {
        lenBytes += String.fromCharCode(len & 0xff);
        len = len >>> 8;
      } while (len > 0);

      // set first byte to # bytes used to store the length and turn on
      // bit 8 to indicate long-form length is used
      bytes.putByte(lenBytes.length | 0x80);

      // concatenate length bytes in reverse since they were generated
      // little endian and we need big endian
      for (let i = lenBytes.length - 1; i >= 0; --i) {
        bytes.putByte(lenBytes.charCodeAt(i));
      }
    }
    bytes.putBuffer(value);
    return bytes;
  }

  static oidToDer(oid: string): ByteStringBuffer {
    // split OID into individual values
    const values = oid.split('.');
    const bytes = new ByteStringBuffer();

    // first byte is 40 * value1 + value2
    bytes.putByte(40 * parseInt(values[0], 10) + parseInt(values[1], 10));
    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
    let last: boolean;
    let valueBytes: number[];
    let value: number;
    let b: number;
    for (let i = 2; i < values.length; ++i) {
      // produce value bytes in reverse because we don't know how many
      // bytes it will take to store the value
      last = true;
      valueBytes = [];
      value = parseInt(values[i], 10);
      do {
        b = value & 0x7f;
        value = value >>> 7;
        // if value is not last, then turn on 8th bit
        if (!last) {
          b |= 0x80;
        }
        valueBytes.push(b);
        last = false;
      } while (value > 0);

      // add value bytes in reverse (needs to be in big endian)
      for (let n = valueBytes.length - 1; n >= 0; --n) {
        bytes.putByte(valueBytes[n]);
      }
    }

    return bytes;
  }

  static derToOid(bytes: string | ByteStringBuffer): string {
    let oid: string;
    // wrap in buffer if needed
    if (typeof bytes === 'string') {
      bytes = new ByteStringBuffer(bytes);
    }

    // first byte is 40 * value1 + value2
    let b = bytes.getByte();
    oid = Math.floor(b / 40) + '.' + (b % 40);

    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
    let value = 0;
    while (bytes.length() > 0) {
      b = bytes.getByte();
      value = value << 7;
      // not the last byte for the value
      if (b & 0x80) {
        value += b & 0x7f;
      } else {
        // last byte
        oid += '.' + (value + b);
        value = 0;
      }
    }

    return oid;
  }

  static integerToDer(x: number): ByteStringBuffer {
    const rval = new ByteStringBuffer();
    if (x >= -0x80 && x < 0x80) {
      return rval.putSignedInt(x, 8);
    }
    if (x >= -0x8000 && x < 0x8000) {
      return rval.putSignedInt(x, 16);
    }
    if (x >= -0x800000 && x < 0x800000) {
      return rval.putSignedInt(x, 24);
    }
    if (x >= -0x80000000 && x < 0x80000000) {
      return rval.putSignedInt(x, 32);
    }
    const error = new Error('Integer too large; max is 32-bits.');
    (error as any).integer = x;
    throw error;
  }
}
