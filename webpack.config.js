const path = require('path');

module.exports = {
    entry: './KeyCloakSDK.js',
    output: {
        filename: 'index.min.js',
        path: path.resolve(__dirname, 'dist'),
    },
    // module: {
    //     rules: [
    //         {
    //             test: /\.(?:js|mjs|cjs)$/,
    //             exclude: /node_modules/,
    //             use: {
    //                 loader: 'babel-loader',
    //                 options: {
    //                     presets: [
    //                         ['@babel/preset-env', { targets: "defaults" }]
    //                     ]
    //                 }
    //             }
    //         }
    //     ],
    // },
};