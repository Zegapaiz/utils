import * as t from '../../src/is/business';
import { expect } from 'chai';
import 'mocha';

describe('IdCard function', () => {
  it('should return asdfasdf', () => {
    const result = t.isIdCard('asdfasdf');
    expect(result).to.equal(false);
  });
});

describe('BankId function', () => {
    it('should return false', () => {
      const result = t.isIdCard('234');
      expect(result).to.equal(false);
    });
    it('should return asdfasdf', () => {
        const result = t.isIdCard('asdfasdf');
        expect(result).to.equal(false);
    });
});