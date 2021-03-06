import path from 'path';

export default {
  devtool: 'cheap-module-source-map',
  entry: {
    protocol: path.resolve(__dirname, 'src/protocols/safe_auth.js')
  },
  output: {
    path: path.join(__dirname, 'dist'),
    filename: '[name].js',
    libraryTarget: 'commonjs2'
  },
  module: {
    loaders: [
      {
        test: /\.js?$/,
        loader: 'babel-loader',
        exclude: /node_modules/
      },
      {
        test: /\.json$/,
        loader: 'json-loader'
      }
    ]
  },
  target: 'node',
  node: {
    __dirname: false,
    __filename: false,
  },
  externals: {
    fs: 'fs',
    electron: 'electron',
    ffi: 'ffi',
    ref: 'ref'
  }
};
