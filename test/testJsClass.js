// TsClass = {
//         abc: function(){
//             console.log('abc', this)
//             this.encode = function() {
//                 this.stop()
//                 // console.log(this)
//             }
//         }
// }
// // const ll = new TsClass().ll

// function sClass(s){
//     return s + "哈哈啊哈哈哈"
// }
// console.log(new sClass('asfsfd'))
// console.log(ll.encode())
// import s from '../index'
const { Event } = require('../index')
const e = new Event()
e.on('shinian',()=>console.log("十娘给你做面汤"))
e.emit('shinian')