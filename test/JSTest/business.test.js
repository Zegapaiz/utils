import {isIdCard} from '../../lib';
import { expect } from 'chai';
import 'mocha';

describe('IdCard function', () => {
  it('should return asdfasdf', () => {
    const result = isIdCard('asdfasdf');
    expect(result).to.equal(false);
  });
});

describe('BankId function', () => {
    it('should return false', () => {
      const result = isIdCard('234');
      expect(result).to.equal(false);
    });
    it('should return asdfasdf', () => {
        const result = isIdCard('asdfasdf');
        expect(result).to.equal(false);
      });
});