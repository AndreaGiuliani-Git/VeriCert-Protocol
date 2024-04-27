"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.setContProv = exports.getResolver = void 0;
var fs = require("fs/promises");
var config = require('../config.json');
var contractInstance;
function getResolver() {
    function resolve(did) {
        return __awaiter(this, void 0, void 0, function () {
            var err, startTime, tx, resolutionTime, csvRow, DID, ethrAccount, didDocumentMetadata, didDocument, docIdMatchesDid, contentType;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        err = null;
                        startTime = performance.now();
                        return [4 /*yield*/, contractInstance.resolutionDID(did.split(":")[3])];
                    case 1:
                        tx = _a.sent();
                        resolutionTime = parseFloat((performance.now() - startTime).toFixed(2));
                        csvRow = "".concat(resolutionTime, "\n");
                        fs.appendFile(config.perfFiles.DIDresolutionPerf, csvRow);
                        DID = "did:ethr:".concat(config.sepolia.net, ":").concat(tx[0]);
                        ethrAccount = tx[1];
                        didDocumentMetadata = {};
                        didDocument = null;
                        do {
                            didDocument = {
                                '@context': [
                                    'https://www.w3.org/ns/did/v1',
                                    'https://w3id.org/security/suites/secp256k1recovery-2020/v2'
                                ],
                                id: DID,
                                verificationMethod: [
                                    {
                                        id: DID + '#controller',
                                        type: 'EcdsaSecp256k1RecoveryMethod2020',
                                        controller: DID,
                                        blockchainAccountId: ethrAccount
                                    }
                                ],
                                authentication: [
                                    DID + '#controller',
                                ],
                            };
                            docIdMatchesDid = (didDocument === null || didDocument === void 0 ? void 0 : didDocument.id) === did;
                            if (!docIdMatchesDid) {
                                err = 'resolver_error: DID document id does not match requested did';
                                break; // uncomment this when adding more checks
                            }
                            // eslint-disable-next-line no-constant-condition
                        } while (false);
                        contentType = typeof (didDocument === null || didDocument === void 0 ? void 0 : didDocument['@context']) !== 'undefined' ? 'application/did+ld+json' : 'application/did+json';
                        if (err) {
                            return [2 /*return*/, {
                                    didDocument: didDocument,
                                    didDocumentMetadata: didDocumentMetadata,
                                    didResolutionMetadata: {
                                        error: 'notFound',
                                        message: err,
                                    },
                                }];
                        }
                        else {
                            return [2 /*return*/, {
                                    didDocument: didDocument,
                                    didDocumentMetadata: didDocumentMetadata,
                                    didResolutionMetadata: { contentType: contentType },
                                }];
                        }
                        return [2 /*return*/];
                }
            });
        });
    }
    return { ethr: resolve };
}
exports.getResolver = getResolver;
function setContProv(contract, provider) {
    contractInstance = contract;
}
exports.setContProv = setContProv;
