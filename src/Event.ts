// 1. 订阅发布机制
// 2. 一个事件可以执行多个函数
// 3. 函数执行要有中间层的概念
// 4. 加入异步函数

class Event {

    private _events: any = {}
    private Middleware: Function[] = []

    constructor(){

    }

    applyMiddleware = (middleware: Function[]): void => {
        this.Middleware = this.Middleware.concat(middleware)
        console.log('applyMiddleware', this.Middleware)
    }

    emit = (type: string, data?: any) => {
        type = type.toLowerCase();
        let eventArr = this._events[type];
        if (!eventArr) return;

        let fn, scope

        // console.log('emit' , this.Middleware)
        for (let i = 0, l = this.Middleware.length; i < l; ++i) {
            this.Middleware[i](type, data);
        }

        for (let i = 0, l = eventArr.length; i < l; ++i) {
            fn = eventArr[i][0];
            scope = eventArr[i][1];
            if (scope) {
                fn.call(scope, data);
            } else {
                fn(data);
            }
        }
        return;
    }
    // 事件绑定方法
    on = (type: string, fn: Function, scope?: any) => {
        // if (type + '' !== type) {
        //     console && console.error && console.error('事件名称必须为字符串！');
        //     return this;
        // }

        // if (typeof fn != 'function') {
        //     console && console.error && console.error('必须是一个函数');
        //     return this;
        // }

        type = type.toLowerCase();

        if (!this._events[type]) {
            this._events[type] = [];
        }

        this._events[type].push(scope ? [fn, scope] : [fn]);

        return this;
    }
    // 删除事件绑定方法
    off = (type: string, fn: Function) => {
        type = type.toLowerCase();

        let eventArr = this._events[type];

        if (!eventArr || !eventArr.length) return;

        if (!fn) {
            this._events[type] = eventArr = [];
        } else {
            for (let i = 0; i < eventArr.length; ++i) {
                if (fn === eventArr[i][0]) {
                    eventArr.splice(i, 1);
                    // 1、找到后不能立即 break 可能存在一个事件一个函数绑定多次的情况
                    // 删除后数组改变，下一个仍然需要遍历处理！
                    --i;
                }
            }
        }
        return;
    }
    dispatch = () => {}
}
export = Event

// const a = new Event()
// a.applyMiddleware([
//     (type:string)=>{
//         console.log('type',type)
//     // result = 'result1'
// },(type:string)=>{
//         console.log('type',type)
//         // result = 'result2'
// }])
// a.emit('abcd');
// // Event.emit('ended')
