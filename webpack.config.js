const webpack = require('webpack');
const path = require('path');

module.exports = {
  entry: './index.js',
  module: {
    rules: [
      {
        test: /\.worker\.(c|m)?js$/i,
        loader: 'worker-loader',
        options: {
          inline: 'no-fallback',
          esModule: true,
        },
      },
    ],
  },
  output: {
    path: path.resolve(__dirname, 'dist_github'),
    library: 'sframe',
    libraryTarget: 'umd',
  },
  devServer: {
    static: {
      directory: path.join(__dirname, 'dist'),
    },
    compress: true,
    port: 9000,
  },
};
