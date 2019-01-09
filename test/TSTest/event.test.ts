import event from '../../src/event/Event';
import { expect } from 'chai';
import 'mocha';

describe('on and emit function', () => {
    it('should return result', () => {
        let result: string;
        event.on('234', () => {
            result = 'result'
        });
        event.emit('234');
        expect(result).to.equal('result');
    });
});

describe('applyMiddleware function', () => {
    it('should return result2', () => {
        let result: string;
        event.applyMiddleware([
            () => {
                result = 'result1'
            }
            , () => {
                result = 'result2'
            }
        ])
        event.on('abcd', () => { console.log('i am camming') });
        event.emit('abcd');
        expect(result).to.equal('result2');
    });
});