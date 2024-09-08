'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.networks = exports.ECPairFactory = exports.default = void 0;
var ecpair_1 = require('./ecpair.cjs');
Object.defineProperty(exports, 'default', {
  enumerable: true,
  get: function () {
    return ecpair_1.ECPairFactory;
  },
});
Object.defineProperty(exports, 'ECPairFactory', {
  enumerable: true,
  get: function () {
    return ecpair_1.ECPairFactory;
  },
});
Object.defineProperty(exports, 'networks', {
  enumerable: true,
  get: function () {
    return ecpair_1.networks;
  },
});
