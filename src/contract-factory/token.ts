import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
import {
  ContractAdapter,
  dummyAddress,
  dummyPadding,
  dummyPayload,
  dummyPk,
  dummyRabinPubKey,
  dummyRabinPubKeyHashArray,
  dummySigBE,
  dummyTx,
  dummyTxId,
  PLACE_HOLDER_SIG,
  Proto,
  Utils,
} from "@sensible-contract/sdk-core";
import {
  buildContractClass,
  Bytes,
  FunctionCall,
  getPreimage,
  Int,
  PubKey,
  Sig,
  SigHashPreimage,
  toHex,
} from "@sensible-contract/sdk-core/lib/scryptlib";
import * as ftProto from "../contract-proto/token.proto";
import { ContractUtil } from "../contractUtil";
import {
  TokenTransferCheckFactory,
  TOKEN_TRANSFER_TYPE,
} from "./tokenTransferCheck";
import {
  TokenUnlockContractCheckFactory,
  TOKEN_UNLOCK_TYPE,
} from "./tokenUnlockContractCheck";

export class Token extends ContractAdapter {
  private constuctParams: {
    transferCheckCodeHashArray: Bytes[];
    unlockContractCodeHashArray: Bytes[];
  };
  private _formatedDataPart: ftProto.FormatedDataPart;

  constructor(constuctParams: {
    transferCheckCodeHashArray: Bytes[];
    unlockContractCodeHashArray: Bytes[];
  }) {
    let desc = require("../contract-desc/token_desc.json");
    let ClassObj = buildContractClass(desc);
    let contract = new ClassObj(
      constuctParams.transferCheckCodeHashArray,
      constuctParams.unlockContractCodeHashArray
    );
    super(contract);

    this.constuctParams = constuctParams;
    this._formatedDataPart = {};
  }

  static fromASM(asm: string) {
    let desc = require("../contract-desc/token_desc.json");
    let ClassObj = buildContractClass(desc);
    let contract = ClassObj.fromASM(asm);
    return contract;
  }

  clone() {
    let contract = new Token(this.constuctParams);
    contract.setFormatedDataPart(this.getFormatedDataPart());
    return contract;
  }

  public setFormatedDataPart(dataPart: ftProto.FormatedDataPart): void {
    this._formatedDataPart = Object.assign(
      {},
      this._formatedDataPart,
      dataPart
    );
    this._formatedDataPart.genesisFlag = ftProto.GENESIS_FLAG.FALSE;
    this._formatedDataPart.protoVersion = ftProto.PROTO_VERSION;
    this._formatedDataPart.protoType = Proto.PROTO_TYPE.FT;
    super.setDataPart(toHex(ftProto.newDataPart(this._formatedDataPart)));
  }

  public getFormatedDataPart() {
    return this._formatedDataPart;
  }

  public unlock({
    txPreimage,
    tokenInputIndex,
    prevouts,
    rabinMsg,
    rabinPaddingArray,
    rabinSigArray,
    rabinPubKeyIndexArray,
    rabinPubKeyVerifyArray,
    rabinPubKeyHashArray,
    checkInputIndex,
    checkScriptTx,
    nReceivers,
    prevTokenAddress,
    prevTokenAmount,
    senderPubKey,
    senderSig,
    lockContractInputIndex,
    lockContractTx,
    operation,
  }: {
    txPreimage: SigHashPreimage;
    tokenInputIndex: number;
    prevouts: Bytes;
    rabinMsg: Bytes;
    rabinPaddingArray: Bytes[];
    rabinSigArray: Int[];
    rabinPubKeyIndexArray: number[];
    rabinPubKeyVerifyArray: Int[];
    rabinPubKeyHashArray: Bytes;
    checkInputIndex: number;
    checkScriptTx: Bytes;
    nReceivers: number;
    prevTokenAddress: Bytes;
    prevTokenAmount: Int;
    senderPubKey?: PubKey; // only transfer need
    senderSig?: Sig; // only transfer need
    lockContractInputIndex?: number; // only unlockFromContract need
    lockContractTx?: Bytes; // only unlockFromContract need
    operation: ftProto.FT_OP_TYPE;
  }) {
    if (operation != ftProto.FT_OP_TYPE.TRANSFER) {
      senderPubKey = new PubKey("00");
      senderSig = new Sig("00");
    }

    if (operation != ftProto.FT_OP_TYPE.UNLOCK_FROM_CONTRACT) {
      lockContractInputIndex = 0;
      lockContractTx = new Bytes("");
    }

    return this._contract.unlock(
      txPreimage,
      tokenInputIndex,
      prevouts,
      rabinMsg,
      rabinPaddingArray,
      rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray,
      rabinPubKeyHashArray,
      checkInputIndex,
      checkScriptTx,
      nReceivers,
      prevTokenAddress,
      prevTokenAmount,
      senderPubKey,
      senderSig,
      lockContractInputIndex,
      lockContractTx,
      operation
    ) as FunctionCall;
  }
}

export class TokenFactory {
  public static lockingScriptSize: number;

  public static getLockingScriptSize() {
    return this.lockingScriptSize;
  }

  public static createContract(
    transferCheckCodeHashArray: Bytes[],
    unlockContractCodeHashArray: Bytes[]
  ): Token {
    return new Token({
      transferCheckCodeHashArray,
      unlockContractCodeHashArray,
    });
  }

  public static getDummyInstance() {
    let contract = this.createContract(
      ContractUtil.transferCheckCodeHashArray,
      ContractUtil.unlockContractCodeHashArray
    );
    contract.setFormatedDataPart({});
    return contract;
  }

  public static calLockingScriptSize() {
    let contract = this.getDummyInstance();
    return (contract.lockingScript as bsv.Script).toBuffer().length;
  }

  public static calTransferUnlockingScriptSize(
    bsvInputLen: number,
    tokenInputLen: number,
    tokenOutputLen: number,
    transferType: TOKEN_TRANSFER_TYPE
  ) {
    let contract = this.getDummyInstance();
    const preimage = getPreimage(dummyTx, contract.lockingScript.toASM(), 1);
    const sig = Buffer.from(PLACE_HOLDER_SIG, "hex");
    const rabinMsg = dummyPayload;
    const rabinPaddingArray: Bytes[] = [];
    const rabinSigArray: Int[] = [];
    const rabinPubKeyIndexArray: number[] = [];
    const rabinPubKeyArray: Int[] = [];
    for (let i = 0; i < ftProto.SIGNER_VERIFY_NUM; i++) {
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

    let routeCheckContact =
      TokenTransferCheckFactory.getDummyInstance(transferType);
    const routeCheckInputIndex = 0;
    let routeCheckTx = new bsv.Transaction(dummyTx.serialize(true));
    routeCheckTx.addOutput(
      new bsv.Transaction.Output({
        script: routeCheckContact.lockingScript,
        satoshis: 10000,
      })
    );

    let unlockedContract = contract.unlock({
      txPreimage: new SigHashPreimage(toHex(preimage)),
      tokenInputIndex,
      prevouts: new Bytes(toHex(prevouts)),
      rabinMsg: new Bytes(toHex(rabinMsg)),
      rabinPaddingArray,
      rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray: rabinPubKeyArray,
      rabinPubKeyHashArray: new Bytes(toHex(dummyRabinPubKeyHashArray)),
      checkInputIndex: routeCheckInputIndex,
      checkScriptTx: new Bytes(routeCheckTx.serialize(true)),
      nReceivers: tokenOutputLen,
      prevTokenAddress: new Bytes(toHex(dummyAddress.hashBuffer)),
      prevTokenAmount: new Int("1000000000"),
      senderPubKey: new PubKey(toHex(dummyPk)),
      senderSig: new Sig(toHex(sig)),
      lockContractInputIndex: 0,
      lockContractTx: new Bytes("00"),
      operation: ftProto.FT_OP_TYPE.TRANSFER,
    });
    return (unlockedContract.toScript() as bsv.Script).toBuffer().length;
  }

  public static calUnlockUnlockingScriptSize(
    bsvInputLen: number,
    lockContractTxRawHex: string,
    tokenInputLen: number,
    tokenOutputLen: number,
    unlockType: TOKEN_UNLOCK_TYPE
  ) {
    let contract = this.getDummyInstance();
    const preimage = getPreimage(dummyTx, contract.lockingScript.toASM(), 1);
    const rabinMsg = dummyPayload;
    const rabinPaddingArray: Bytes[] = [];
    const rabinSigArray: Int[] = [];
    const rabinPubKeyIndexArray: number[] = [];
    const rabinPubKeyArray: Int[] = [];
    for (let i = 0; i < ftProto.SIGNER_VERIFY_NUM; i++) {
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
    const routeCheckInputIndex = 0;

    let unlockCheckContract =
      TokenUnlockContractCheckFactory.getDummyInstance(unlockType);

    let routeCheckTx = new bsv.Transaction(dummyTx.serialize(true));
    routeCheckTx.addOutput(
      new bsv.Transaction.Output({
        script: unlockCheckContract.lockingScript,
        satoshis: 10000,
      })
    );

    let unlockedContract = contract.unlock({
      txPreimage: new SigHashPreimage(toHex(preimage)),
      tokenInputIndex,
      prevouts: new Bytes(toHex(prevouts)),
      rabinMsg: new Bytes(toHex(rabinMsg)),
      rabinPaddingArray,
      rabinSigArray,
      rabinPubKeyIndexArray,
      rabinPubKeyVerifyArray: rabinPubKeyArray,
      rabinPubKeyHashArray: new Bytes(toHex(dummyRabinPubKeyHashArray)),
      checkInputIndex: routeCheckInputIndex,
      checkScriptTx: new Bytes(routeCheckTx.serialize(true)),
      nReceivers: tokenOutputLen,
      prevTokenAddress: new Bytes(toHex(dummyAddress.hashBuffer)),
      prevTokenAmount: new Int("1000000000"),
      senderPubKey: new PubKey("00"),
      senderSig: new Sig("00"),
      lockContractInputIndex: 0,
      lockContractTx: new Bytes(lockContractTxRawHex),
      operation: ftProto.FT_OP_TYPE.UNLOCK_FROM_CONTRACT,
    });
    return (unlockedContract.toScript() as bsv.Script).toBuffer().length;
  }
}
