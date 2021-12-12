import * as bsv from "@sensible-contract/bsv";
import { BN } from "@sensible-contract/bsv";
import { InputInfo, SatotxSigner } from "@sensible-contract/sdk-core";
import {
  dummyRabinKeypairs,
  MockProvider,
  MockSatotxApi,
} from "@sensible-contract/test-utils";
import { TOKEN_TRANSFER_TYPE } from "../src/contract-factory/tokenTransferCheck";
import {
  SIGNER_NUM,
  SIGNER_VERIFY_NUM,
} from "../src/contract-proto/token.proto";
import {
  createTokenGenesisTx,
  createTokenIssueTx,
  createTokenTransferCheckContractTx,
  createTokenTransferTx,
  getTokenGenesisInfo,
  getTokenGenesisInput,
  getTokenInputs,
  TokenSigner,
} from "../src/index";
const signerNum = SIGNER_NUM;
const signerVerifyNum = SIGNER_VERIFY_NUM;
const satotxSigners: SatotxSigner[] = [];
for (let i = 0; i < signerNum; i++) {
  let { p, q } = dummyRabinKeypairs[i];
  let satotxSigner = new SatotxSigner();
  let mockSatotxApi = new MockSatotxApi(
    BN.fromString(p, 10),
    BN.fromString(q, 10)
  );
  satotxSigner.satotxApi = mockSatotxApi as any;
  satotxSigner.satotxPubKey = mockSatotxApi.satotxPubKey;
  satotxSigners.push(satotxSigner);
}
const signerSelecteds = new Array(signerNum)
  .fill(0)
  .map((v, idx) => idx)
  // .sort((a, b) => Math.random() - 0.5)
  .slice(0, signerVerifyNum);
let wallets: {
  privateKey: bsv.PrivateKey;
  publicKey: string;
  address: string;
}[] = [];
let wifs = [
  "L3tez3Lj3g7n4eZQf8jx6PUN8rnoTxZiiCf153U2ZRyNK4gPd1Je",
  "L3gKYZ3a3SRcteQe7gpahAYDxQbYxxRjtmpSg46Dh2AUE9pUjcWp",
  "L4F6T4hLnT7URMEEFKZq7qcTwvXS7w4BURoV8MyPurvMUgNy5sMM",
  "L12XGk7dErVzH5VyXGXPr5xP49xuLhgpUEFfQU4FzTJLieKGNbtQ",
];
for (let i = 0; i < 4; i++) {
  let privateKey = new bsv.PrivateKey(wifs[i]);
  wallets.push({
    privateKey,
    publicKey: privateKey.publicKey.toString(),
    address: privateKey.toAddress("mainnet").toString(),
  });
}

let [FeePayer, CoffeeShop, Alice, Bob] = wallets;
console.log(`
FeePayer:   ${FeePayer.address.toString()}
CoffeeShop: ${CoffeeShop.address.toString()}
Alice:      ${Alice.address.toString()}
Bob:        ${Bob.address.toString()}
`);

function signSigHashList(txHex: string, sigHashList: InputInfo[]) {
  const tx = new bsv.Transaction(txHex);
  let sigList = sigHashList.map((v) => {
    let privateKey = wallets.find((w) => w.address == v.address).privateKey;
    let sighash = bsv.Transaction.Sighash.sighash(
      tx,
      v.sighashType,
      v.inputIndex,
      new bsv.Script(v.scriptHex),
      new bsv.crypto.BN(v.satoshis)
    ).toString("hex");

    var sig = bsv.crypto.ECDSA.sign(
      Buffer.from(sighash, "hex"),
      privateKey,
      "little"
    )
      .set({
        nhashtype: v.sighashType,
      })
      .toString();
    return {
      sig,
      publicKey: privateKey.toPublicKey().toString(),
    };
  });
  return sigList;
}

let mockProvider = new MockProvider();
async function genDummyFeeUtxos(satoshis: number, count: number = 1) {
  let feeTx = new bsv.Transaction();
  let unitSatoshis = Math.ceil(satoshis / count);
  let satoshisArray = [];

  for (let i = 0; i < count; i++) {
    if (satoshis < unitSatoshis) {
      satoshisArray.push(satoshis);
    } else {
      satoshisArray.push(unitSatoshis);
    }
    satoshis -= unitSatoshis;
  }
  for (let i = 0; i < count; i++) {
    feeTx.addOutput(
      new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(FeePayer.address),
        satoshis: satoshisArray[i],
      })
    );
  }
  let utxos = [];
  for (let i = 0; i < count; i++) {
    utxos.push({
      txId: feeTx.id,
      outputIndex: i,
      satoshis: satoshisArray[i],
      address: FeePayer.address.toString(),
      wif: FeePayer.privateKey.toWIF(),
    });
  }
  await mockProvider.pushTx(feeTx.serialize(true));
  return utxos;
}

function cleanBsvUtxos() {
  mockProvider.cleanBsvUtxos();
}

describe("Token Test", () => {
  describe("basic test ", () => {
    let provider: MockProvider;
    let tokenSigner: TokenSigner;
    let codehash: string;
    let genesis: string;
    let sensibleId: string;
    const opreturnData = "";

    before(async () => {
      provider = mockProvider;
      provider.network = "mainnet";

      tokenSigner = new TokenSigner({
        signerSelecteds,
        signerConfigs: satotxSigners.map((v) => ({
          satotxApiPrefix: "",
          satotxPubKey: v.satotxPubKey.toString("hex"),
        })),
      });
      tokenSigner.signers = satotxSigners;
      mockProvider.cleanCacheds();
    });

    it("genesis token should be ok", async () => {
      let estimateFee = createTokenGenesisTx.estimateFee({
        utxoMaxCount: 1,
      });
      let utxos = await genDummyFeeUtxos(estimateFee);

      let { txComposer } = await createTokenGenesisTx({
        tokenSigner,
        tokenName: "CoffeeCoin",
        tokenSymbol: "CC",
        decimalNum: 8,
        genesisPublicKey: CoffeeShop.publicKey,
        utxos,
      });

      let sigResults = signSigHashList(
        txComposer.getRawHex(),
        txComposer.getInputInfos()
      );
      txComposer.unlock(sigResults);
      let _res = getTokenGenesisInfo(tokenSigner, txComposer.getRawHex());
      await mockProvider.broadcast(txComposer.getRawHex());
      txComposer.checkFeeRate();
      genesis = _res.genesis;
      codehash = _res.codehash;
      sensibleId = _res.sensibleId;
    });
    it("issue token should be ok", async () => {
      cleanBsvUtxos();

      let { genesisInput, genesisContract } = await getTokenGenesisInput(
        provider,
        { sensibleId }
      );
      let estimateFee = createTokenIssueTx.estimateFee({
        genesisInput,
        allowIncreaseIssues: true,
        opreturnData,
      });
      let utxos = await genDummyFeeUtxos(estimateFee);

      let { txComposer } = await createTokenIssueTx({
        tokenSigner,
        genesisInput,
        genesisContract,
        receiverAddress: CoffeeShop.address.toString(),
        tokenAmount: "1000",
        allowIncreaseIssues: false,
        utxos,
      });
      let sigResults = signSigHashList(
        txComposer.getRawHex(),
        txComposer.getInputInfos()
      );
      txComposer.unlock(sigResults);
      await mockProvider.broadcast(txComposer.getRawHex());
      txComposer.checkFeeRate();
    });

    it("transfer should be ok", async () => {
      cleanBsvUtxos();

      let tokenUtxos = await provider.getTokenUtxos(
        codehash,
        genesis,
        CoffeeShop.address
      );

      let tokenOutputs = [
        {
          address: Alice.address,
          amount: "1000",
        },
      ];
      let tokenInputs = await getTokenInputs(provider, {
        tokenSigner,
        tokenUtxos,
        codehash,
        genesis,
      });

      let utxoMaxCount = 3;
      let tokenTransferType = TOKEN_TRANSFER_TYPE.IN_6_OUT_6;
      let fee1 = createTokenTransferCheckContractTx.estimateFee({
        tokenTransferType,
        utxoMaxCount,
      });
      let fee2 = createTokenTransferTx.estimateFee({
        tokenInputs,
        tokenOutputs,
        tokenTransferType,
        utxoMaxCount: 1,
        opreturnData,
      });
      let utxos = await genDummyFeeUtxos(fee1 + fee2);

      let transferCheckRet = await createTokenTransferCheckContractTx({
        tokenTransferType,
        tokenInputCount: tokenInputs.length,
        tokenOutputs,
        codehash,
        tokenID: tokenInputs[0].tokenID,
        utxos,
      });

      transferCheckRet.txComposer.unlock(
        signSigHashList(
          transferCheckRet.txComposer.getRawHex(),
          transferCheckRet.txComposer.getInputInfos()
        )
      );

      utxos = [transferCheckRet.txComposer.getChangeUtxo()];

      let { txComposer } = await createTokenTransferTx({
        tokenSigner,
        tokenInputs,
        tokenOutputs,
        transferCheckContract: transferCheckRet.transferCheckContract,
        transferCheckTxComposer: transferCheckRet.txComposer,
        utxos,
      });

      txComposer.unlock(
        signSigHashList(txComposer.getRawHex(), txComposer.getInputInfos())
      );

      txComposer.dumpTx();

      await mockProvider.broadcast(transferCheckRet.txComposer.getRawHex());
      await mockProvider.broadcast(txComposer.getRawHex());
    });
  });
});
