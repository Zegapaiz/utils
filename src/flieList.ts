
// import readline = require('readline');
// const path = require('path');
const fs = require('fs');
// import os = require('os');
// const models = path.resolve( __dirname,'../src/is' )


    // .forEach((file:any)=> require(path.resolve(models, file)))

export = function(path:string, suffix?: string){
    if(suffix) return fs.readdirSync(path).filter((file:any)=> ~file.search(new RegExp(`^[^\.].*.${suffix}$`)))
    else return fs.readdirSync(path)
}

    // require(path.resolve(models, file))
// console.log(__dirname)
// console.log(path.join(__dirname, "./is/business.ts"))



// export = require('query-string') 