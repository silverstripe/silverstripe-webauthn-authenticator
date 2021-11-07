/* global jest, describe, it, expect, window */

import { base64ToByteArray, byteArrayToBase64 } from '../convert';

describe('convert', () => {
    it('converts base64ToByteArray', () => {
        const string = 'abc/def+ghi';
        const expected = new Uint8Array([105, 183, 63, 117, 231, 254, 130, 24]);
        const actual = base64ToByteArray(string);
        expect(expected).toEqual(actual);
    });

    it('converts base64ToByteArray when encoded web-safe', () => {
        const string = 'abc_def-ghi';
        const expected = new Uint8Array([105, 183, 63, 117, 231, 254, 130, 24]);
        const actual = base64ToByteArray(string);
        expect(expected).toEqual(actual);
    });

    it('converts byteArrayToBase64', () => {
        const byteArray = [105, 183, 63, 117, 231, 254, 130, 24];
        // this is supposed to be slightly different from string
        // used in base64ToByteArray tests
        const expected = 'abc/def+ghg=';
        const actual = byteArrayToBase64(byteArray);
        expect(expected).toEqual(actual);
    });
});
