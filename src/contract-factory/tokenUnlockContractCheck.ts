import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
import {
  ContractAdapter,
  dummyAddress,
  dummyCodehash,
  dummyPadding,
  dummyPayload,
  dummyRabinPubKey,
  dummyRabinPubKeyHashArray,
  dummySigBE,
  dummyTx,
  dummyTxId,
  RABIN_SIG_LEN,
  Utils,
} from "@sensible-contract/sdk-core";
import {
  buildContractClass,
  Bytes,
  FunctionCall,
  getPreimage,
  Int,
  SigHashPreimage,
  toHex,
} from "@sensible-contract/sdk-core/lib/scryptlib";
import { SIGNER_VERIFY_NUM } from "../contract-proto/token.proto";
import * as proto from "../contract-proto/tokenUnlockContractCheck.proto";
import { TokenFactory } from "./token";

export enum TOKEN_UNLOCK_TYPE {
  IN_2_OUT_5 = 1,
  IN_4_OUT_8,
  IN_8_OUT_12,
  IN_3_OUT_100,
  IN_20_OUT_5,
  UNSUPPORT,
}

let _tokenUnlockTypeInfos = [
  {
    type: TOKEN_UNLOCK_TYPE.IN_2_OUT_5,
    in: 2,
    out: 5,
    lockingScriptSize: 0,
  },
  {
    type: TOKEN_UNLOCK_TYPE.IN_4_OUT_8,
    in: 4,
    out: 8,
    lockingScriptSize: 0,
  },
  {
    type: TOKEN_UNLOCK_TYPE.IN_8_OUT_12,
    in: 8,
    out: 12,
    lockingScriptSize: 0,
  },
  {
    type: TOKEN_UNLOCK_TYPE.IN_20_OUT_5,
    in: 20,
    out: 5,
    lockingScriptSize: 0,
  },
  {
    type: TOKEN_UNLOCK_TYPE.IN_3_OUT_100,
    in: 3,
    out: 100,
    lockingScriptSize: 0,
  },
];

export class TokenUnlockContractCheck extends ContractAdapter {
  constuctParams: {
    unlockType: TOKEN_UNLOCK_TYPE;
  };
  private _formatedDataPart: proto.FormatedDataPart;

  constructor(constuctParams: { unlockType: TOKEN_UNLOCK_TYPE }) {
    let desc;

    switch (constuctParams.unlockType) {
      case TOKEN_UNLOCK_TYPE.IN_2_OUT_5:
        desc = require("../contract-desc/tokenUnlockContractCheck_desc.json");
        break;
      case TOKEN_UNLOCK_TYPE.IN_4_OUT_8:
        desc = require("../contract-desc/tokenUnlockContractCheck_4To8_desc.json");
        break;
      case TOKEN_UNLOCK_TYPE.IN_8_OUT_12:
        desc = require("../contract-desc/tokenUnlockContractCheck_8To12_desc.json");
        break;
      case TOKEN_UNLOCK_TYPE.IN_3_OUT_100:
        desc = require("../contract-desc/tokenUnlockContractCheck_3To100_desc.json");
        break;
      case TOKEN_UNLOCK_TYPE.IN_20_OUT_5:
        desc = require("../contract-desc/tokenUnlockContractCheck_20To5_desc.json");
        break;
      default:
        throw "invalid unlockType";
    }

    let ClassObj = buildContractClass(desc);
    let contract = new ClassObj();
    super(contract);

    this.constuctParams = constuctParams;
    this._formatedDataPart = {};
  }

  clone() {
    let contract = new TokenUnlockContractCheck(this.constuctParams);
    contract.setFormatedDataPart(this.getFormatedDataPart());
    return contract;
  }

  public setFormatedDataPart(dataPart: proto.FormatedDataPart): void {
    this._formatedDataPart = Object.assign(
      {},
      this._formatedDataPart,
      dataPart
    );
    super.setDataPart(toHex(proto.newDataPart(this._formatedDataPart)));
  }

  public getFormatedDataPart() {
    return this._formatedDataPart;
  }

  public unlock({
    txPreimage,
    tokenScript,
    prevouts,
    rabinMsgArray,
    rabinPaddingArray,
    rabinSigArray,
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
    rabinPubKeyHashArray,
    inputTokenAddressArray,
    inputTokenAmountArray,
    nOutputs,
    tokenOutputIndexArray,
    tokenOutputSatoshiArray,
    otherOutputArray,
  }: {
    txPreimage: SigHashPreimage;
    tokenScript: Bytes;
    prevouts: Bytes;
    rabinMsgArray: Bytes;
    rabinPaddingArray: Bytes;
    rabinSigArray: Bytes;
    rabinPubKeyIndexArray: number[];
    rabinPubKeyVerifyArray: Int[];
    rabinPubKeyHashArray: Bytes;
    inputTokenAddressArray: Bytes;
    inputTokenAmountArray: Bytes;
    nOutputs: number;
    tokenOutputIndexArray: Bytes;
    tokenOutputSatoshiArray: Bytes;
    otherOutputArray: Bytes;
  }) {
    return this._contract.unlock(
      txPreimage,
      tokenScript,
      prevouts,
      rabinMsgArray,
      rabinPaddingArray,
      rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray,
      rabinPubKeyHashArray,
      inputTokenAddressArray,
      inputTokenAmountArray,
      nOutputs,
      tokenOutputIndexArray,
      tokenOutputSatoshiArray,
      otherOutputArray
    ) as FunctionCall;
  }
}

export class TokenUnlockContractCheckFactory {
  public static tokenUnlockTypeInfos: {
    type: TOKEN_UNLOCK_TYPE;
    in: number;
    out: number;
    lockingScriptSize: number;
  }[] = _tokenUnlockTypeInfos;

  public static getLockingScriptSize(unlockType: TOKEN_UNLOCK_TYPE) {
    return this.tokenUnlockTypeInfos.find((v) => v.type == unlockType)
      .lockingScriptSize;
  }

  public static getOptimumType(inCount: number, outCount: number) {
    if (inCount <= 2 && outCount <= 5) {
      return TOKEN_UNLOCK_TYPE.IN_2_OUT_5;
    } else if (inCount <= 4 && outCount <= 8) {
      return TOKEN_UNLOCK_TYPE.IN_4_OUT_8;
    } else if (inCount <= 8 && outCount <= 12) {
      return TOKEN_UNLOCK_TYPE.IN_8_OUT_12;
    } else if (inCount <= 20 && outCount <= 5) {
      return TOKEN_UNLOCK_TYPE.IN_20_OUT_5;
    } else if (inCount <= 3 && outCount <= 100) {
      return TOKEN_UNLOCK_TYPE.IN_3_OUT_100;
    } else {
      return TOKEN_UNLOCK_TYPE.UNSUPPORT;
    }
  }

  public static createContract(unlockType: TOKEN_UNLOCK_TYPE) {
    return new TokenUnlockContractCheck({ unlockType });
  }

  public static getDummyInstance(unlockType: TOKEN_UNLOCK_TYPE) {
    let v = this.tokenUnlockTypeInfos.find((v) => v.type == unlockType);
    let tokenInputArray = new Array(v.in).fill(0);
    let tokenOutputArray = new Array(v.out).fill({
      address: dummyAddress,
      tokenAmount: BN.Zero,
    });
    let contract = this.createContract(v.type);
    contract.setFormatedDataPart({
      nSenders: tokenInputArray.length,
      inputTokenIndexArray: new Array(v.in).fill(0),
      nReceivers: tokenOutputArray.length,
      receiverArray: tokenOutputArray.map((v) => v.address),
      receiverTokenAmountArray: tokenOutputArray.map((v) => v.tokenAmount),
      tokenCodeHash: toHex(dummyCodehash),
      tokenID: toHex(dummyCodehash),
    });
    return contract;
  }

  public static calLockingScriptSize(unlockType: TOKEN_UNLOCK_TYPE): number {
    let contract = this.getDummyInstance(unlockType);
    return (contract.lockingScript as bsv.Script).toBuffer().length;
  }

  public static calUnlockingScriptSize(
    unlockType: TOKEN_UNLOCK_TYPE,
    bsvInputLen: number,
    tokenInputLen: number,
    tokenOutputLen: number,
    nOutputLen: number,
    otherOutputArray: Bytes
  ): number {
    let contract = this.getDummyInstance(unlockType);
    let tokenContractInstance = TokenFactory.getDummyInstance();

    const preimage = getPreimage(dummyTx, contract.lockingScript.toASM(), 1);

    let checkRabinMsgArray = Buffer.alloc(0);
    let checkRabinSigArray = Buffer.alloc(0);
    let checkRabinPaddingArray = Buffer.alloc(0);
    let paddingCountBuf = Buffer.alloc(2, 0);
    paddingCountBuf.writeUInt16LE(dummyPadding.length / 2);
    const padding = Buffer.alloc(dummyPadding.length / 2, 0);
    padding.write(dummyPadding, "hex");

    const rabinPaddingArray: Bytes[] = [];
    const rabinSigArray: Int[] = [];
    const rabinPubKeyIndexArray: number[] = [];
    const rabinPubKeyArray: Int[] = [];
    const sigBuf = Utils.toBufferLE(dummySigBE, RABIN_SIG_LEN);
    let inputTokenAddressArray = Buffer.alloc(0);
    let inputTokenAmountArray = Buffer.alloc(0);
    let tokenAmount = Buffer.alloc(8);
    tokenAmount.writeInt32BE(100000);
    for (let i = 0; i < tokenInputLen; i++) {
      inputTokenAddressArray = Buffer.concat([
        inputTokenAddressArray,
        dummyAddress.toBuffer(),
      ]);
      inputTokenAmountArray = Buffer.concat([
        inputTokenAmountArray,
        tokenAmount,
      ]);
      for (let j = 0; j < SIGNER_VERIFY_NUM; j++) {
        if (j == 0) {
          checkRabinMsgArray = Buffer.concat([
            checkRabinMsgArray,
            Buffer.from(dummyPayload, "hex"),
          ]);
        }

        checkRabinSigArray = Buffer.concat([checkRabinSigArray, sigBuf]);

        checkRabinPaddingArray = Buffer.concat([
          checkRabinPaddingArray,
          paddingCountBuf,
          padding,
        ]);
      }
    }
    for (let i = 0; i < SIGNER_VERIFY_NUM; i++) {
      rabinPaddingArray.push(new Bytes(dummyPadding));
      rabinSigArray.push(new Int(BN.fromString(dummySigBE, 16).toString(10)));
      rabinPubKeyIndexArray.push(i);
      rabinPubKeyArray.push(new Int(dummyRabinPubKey.toString(10)));
    }

    const tokenInputIndex = 0;
    let prevouts = Buffer.alloc(0);
    const indexBuf = Utils.getUInt32Buf(0);
    const txidBuf = Utils.getTxIdBuf(dummyTxId);
    for (let i = 0; i < tokenInputLen + bsvInputLen + 1; i++) {
      prevouts = Buffer.concat([prevouts, txidBuf, indexBuf]);
    }

    let tokenOutputIndexArray = Buffer.alloc(0);
    let tokenOutputSatoshiArray = Buffer.alloc(0);

    let receiverSatoshiArray = Buffer.alloc(0);
    for (let i = 0; i < tokenOutputLen; i++) {
      receiverSatoshiArray = Buffer.concat([
        receiverSatoshiArray,
        Buffer.alloc(8),
      ]);

      tokenOutputIndexArray = Buffer.concat([
        tokenOutputIndexArray,
        Buffer.alloc(8),
      ]);

      tokenOutputSatoshiArray = Buffer.concat([
        tokenOutputSatoshiArray,
        Buffer.alloc(8),
      ]);
    }

    let unlockedContract = contract.unlock({
      txPreimage: new SigHashPreimage(toHex(preimage)),
      tokenScript: new Bytes(tokenContractInstance.lockingScript.toHex()),
      prevouts: new Bytes(toHex(prevouts)),
      rabinMsgArray: new Bytes(toHex(checkRabinMsgArray)),
      rabinPaddingArray: new Bytes(toHex(checkRabinPaddingArray)),
      rabinSigArray: new Bytes(toHex(checkRabinSigArray)),
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray: rabinPubKeyArray,
      rabinPubKeyHashArray: new Bytes(toHex(dummyRabinPubKeyHashArray)),
      inputTokenAddressArray: new Bytes(toHex(inputTokenAddressArray)),
      inputTokenAmountArray: new Bytes(toHex(inputTokenAmountArray)),
      nOutputs: nOutputLen,
      tokenOutputIndexArray: new Bytes(toHex(tokenOutputIndexArray)),
      tokenOutputSatoshiArray: new Bytes(toHex(tokenOutputSatoshiArray)),
      otherOutputArray,
    });
    return (unlockedContract.toScript() as bsv.Script).toBuffer().length;
  }
}
