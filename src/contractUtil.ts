import * as bsv from "@sensible-contract/bsv";
import { Bytes, toHex } from "@sensible-contract/sdk-core/lib/scryptlib";
import { TokenFactory } from "./contract-factory/token";
import { TokenGenesisFactory } from "./contract-factory/tokenGenesis";
import {
  TokenTransferCheckFactory,
  TOKEN_TRANSFER_TYPE,
} from "./contract-factory/tokenTransferCheck";
import {
  TokenUnlockContractCheckFactory,
  TOKEN_UNLOCK_TYPE,
} from "./contract-factory/tokenUnlockContractCheck";

function getTokenTransferCheckCodeHashArray(): string[] {
  let contractArray = [
    TokenTransferCheckFactory.createContract(TOKEN_TRANSFER_TYPE.IN_3_OUT_3),
    TokenTransferCheckFactory.createContract(TOKEN_TRANSFER_TYPE.IN_6_OUT_6),
    TokenTransferCheckFactory.createContract(TOKEN_TRANSFER_TYPE.IN_10_OUT_10),
    TokenTransferCheckFactory.createContract(TOKEN_TRANSFER_TYPE.IN_20_OUT_3),
    TokenTransferCheckFactory.createContract(TOKEN_TRANSFER_TYPE.IN_3_OUT_100),
  ];
  return contractArray.map((v) => v.getCodeHash());
}

function getTokenUnlockContractCheckCodeHashArray(): string[] {
  let contractArray = [
    TokenUnlockContractCheckFactory.createContract(
      TOKEN_UNLOCK_TYPE.IN_2_OUT_5
    ),
    TokenUnlockContractCheckFactory.createContract(
      TOKEN_UNLOCK_TYPE.IN_4_OUT_8
    ),
    TokenUnlockContractCheckFactory.createContract(
      TOKEN_UNLOCK_TYPE.IN_8_OUT_12
    ),
    TokenUnlockContractCheckFactory.createContract(
      TOKEN_UNLOCK_TYPE.IN_20_OUT_5
    ),
    TokenUnlockContractCheckFactory.createContract(
      TOKEN_UNLOCK_TYPE.IN_3_OUT_100
    ),
  ];
  return contractArray.map((v) => v.getCodeHash());
}

type ContractConfig = {
  transferCheckCodeHashArray: string[];
  unlockContractCodeHashArray: string[];
  tokenGenesisSize: number;
  tokenSize: number;
  tokenTransferCheckSizes: number[];
  tokenUnlockCheckSizes: number[];
};

const dumpedConfig = {
  transferCheckCodeHashArray: [
    "26d28893e113878cf1ee9a7e895003a49f5ef013",
    "6dafb4298d50713aee751db5b4b1d461772c66bf",
    "4b13250b944e9ca666097213669b36400ae9cbc3",
    "3338b7555dbc9de4ebbf2be3ea4261c2d117baa9",
    "53b9f1a62095df4ab2b0681aeb9adfdc173a8f5c",
  ],
  unlockContractCodeHashArray: [
    "87d174e897fbe7b787e628b154feb22f43341940",
    "ae9b475cad88fb356b24ca51219bfb07d4393dde",
    "fdbfd4daec4ce5adfc2a31238e03b9eb8c57cfb1",
    "e8b08573143899a500b61e5428ed365cc6a2705c",
    "cc884b7b33e212718a4afdac5c95aac25aa80912",
  ],
  tokenGenesisSize: 4999,
  tokenSize: 5626,
  tokenTransferCheckSizes: [5668, 9445, 14482, 21498, 38261],
  tokenUnlockCheckSizes: [7168, 11329, 18273, 25994, 74116],
};

export class ContractUtil {
  static transferCheckCodeHashArray: Bytes[];
  static unlockContractCodeHashArray: Bytes[];
  static tokenCodeHash: string;
  public static init(config: ContractConfig = dumpedConfig) {
    //debug
    // config = this.dumpConfig();

    this.transferCheckCodeHashArray = config.transferCheckCodeHashArray.map(
      (v) => new Bytes(v)
    );
    this.unlockContractCodeHashArray = config.unlockContractCodeHashArray.map(
      (v) => new Bytes(v)
    );
    TokenGenesisFactory.lockingScriptSize = config.tokenGenesisSize;
    TokenFactory.lockingScriptSize = config.tokenSize;
    TokenTransferCheckFactory.tokenTransferTypeInfos.forEach((v, idx) => {
      v.lockingScriptSize = config.tokenTransferCheckSizes[idx];
    });
    TokenUnlockContractCheckFactory.tokenUnlockTypeInfos.forEach((v, idx) => {
      v.lockingScriptSize = config.tokenUnlockCheckSizes[idx];
    });

    let tokenContract = TokenFactory.getDummyInstance();
    tokenContract.setDataPart("");
    let scriptBuf = tokenContract.lockingScript.toBuffer();
    this.tokenCodeHash = toHex(bsv.crypto.Hash.sha256ripemd160(scriptBuf));
  }

  static dumpConfig() {
    let config: ContractConfig = {
      transferCheckCodeHashArray: [],
      unlockContractCodeHashArray: [],
      tokenGenesisSize: 0,
      tokenSize: 0,
      tokenTransferCheckSizes: [],
      tokenUnlockCheckSizes: [],
    };
    config.transferCheckCodeHashArray = getTokenTransferCheckCodeHashArray();
    this.transferCheckCodeHashArray = config.transferCheckCodeHashArray.map(
      (v) => new Bytes(v)
    );

    config.unlockContractCodeHashArray =
      getTokenUnlockContractCheckCodeHashArray();
    this.unlockContractCodeHashArray = config.unlockContractCodeHashArray.map(
      (v) => new Bytes(v)
    );

    config.tokenGenesisSize = TokenGenesisFactory.calLockingScriptSize();
    TokenGenesisFactory.lockingScriptSize = config.tokenGenesisSize;

    config.tokenSize = TokenFactory.calLockingScriptSize();
    TokenFactory.lockingScriptSize = config.tokenSize;

    config.tokenTransferCheckSizes =
      TokenTransferCheckFactory.tokenTransferTypeInfos.map((v) =>
        TokenTransferCheckFactory.calLockingScriptSize(v.type)
      );

    config.tokenUnlockCheckSizes =
      TokenUnlockContractCheckFactory.tokenUnlockTypeInfos.map((v) =>
        TokenUnlockContractCheckFactory.calLockingScriptSize(v.type)
      );

    console.log(JSON.stringify(config));
    return config;
  }
}
