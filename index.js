'use strict'

const crypto = require('crypto')

const NIL_STRING = 'n'
const UNICODE_STRING = 'u'
const BOOLEAN_STRING = 'b'
const INT_STRING = 'i'
const FLOAT_STRING = 'f'
const LIST_STRING = 'l'
const DICT_STRING = 'd'
const REDACTED_REGEX = /^\*\*REDACTED\*\*[0-9a-f]{64}$/i

function hash(str, buf) {
  const bufToHash = Buffer.concat([
    Buffer.from(str, 'utf8'),
    buf])
  const h = crypto.createHash('sha256')
  h.update(bufToHash)
  return h.digest()
}

function sortHashes(bufA, bufB) {
  const a = bufA.toString('hex')
  const b = bufB.toString('hex')
  if (a < b) {
    return -1
  } else if (a > b) {
    return 1
  } else {
    return 0
  }
}

function normalizeFloat (float) {
  let str = ''

  // special case 0
  if (float === 0) {
    return '+0:'
  }

  // sign
  if (float < 0) {
    str = '-'
    float *= -1
  } else {
    str = '+'
  }

  // exponent
  let exponent = 0
  while (float > 1) {
    float = float /2
    exponent++
  }
  while (float <= 0.5) {
    float = float * 2
    exponent--
  }
  str += exponent + ':'

  // mantissa
  while (float !== 0) {
    if (float >= 1) {
      str += '1'
      float --
    } else {
      str += '0'
    }

    if (str.length >= 1000 || float >= 1) {
      throw new Error('invalid number: ' + float.toString())
    }

    float *= 2
  }

  return str
}

function hashDict (obj, options) {
  const hashes = Object.keys(obj).map(function (key) {
    return Buffer.concat([
      objectHash(key, options),
      objectHash(obj[key], options)])
  })
  hashes.sort(sortHashes)
  return hash(DICT_STRING, Buffer.concat(hashes))
}

function hashArray(arr, options) {
  const hashes = arr.map(item => objectHash(item, options))
  if (options.ignoreArrayItemOrder) {
    hashes.sort(sortHashes)
  }
  return hash(LIST_STRING, Buffer.concat(hashes))
}

/**
 *
 * @param {*} obj The value to hash
 * @param {object} [options] Optional settings to tweak the algorithm.
 *
 * - **ignoreArrayItemOrder: boolean (default: `false`)**
 *   When `true` then arrays with the same items but different item order will
 *   yield the same array hash sum. This may be useful to quickly test whether
 *   two arrays contain the same items independent of the item position.
 *
 * Note that when comparing hashes, both hashes must have been produced with
 * identical options.
 */
function objectHash(obj, options) {
  options = options || {};
  if (typeof obj === 'string' && REDACTED_REGEX.test(obj)) {
    return Buffer.from(obj.slice(12), 'hex')
  } else if (typeof obj === 'undefined' || obj === null) {
    return hash(NIL_STRING, Buffer.alloc(0))
  } else if (typeof obj === 'boolean') {
    return hash(BOOLEAN_STRING, Buffer.from((obj ? '1' : '0'), 'utf8'))
  } else if (typeof obj === 'string') {
    return hash(UNICODE_STRING, Buffer.from(obj, 'utf8'))
      /*
  } else if (Number.isInteger(obj)) {
    // note that JS interprets 10.0 as an integer,
    // which may differ from implementations in other languages
    return hash(INT_STRING, Buffer.from('' + obj, 'utf8'))
    */
  } else if (typeof obj === 'number') {
    return hash(FLOAT_STRING, Buffer.from(normalizeFloat(obj), 'utf8'))
  } else if (Array.isArray(obj)) {
    return hashArray(obj, options)
  } else if (typeof obj === 'object') {
    return hashDict(obj, options)
  } else {
    throw new Error('unknown type: ' + typeof obj, obj)
  }
}

module.exports = objectHash

