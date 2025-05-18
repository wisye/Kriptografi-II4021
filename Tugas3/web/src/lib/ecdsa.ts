import { sha3_256 } from "js-sha3";
import { ec as EC } from "elliptic";

const ec = new EC("secp256k1");

export const generateKeyPair = () => {
  const key = ec.genKeyPair();
  const privKey = key.getPrivate("hex");
  const pubKey = key.getPublic();
  const pubKeyX = pubKey.getX().toString("hex").padStart(64, "0");
  const pubKeyY = pubKey.getY().toString("hex").padStart(64, "0");
  return { privKey, pubKeyX: "0x" + pubKeyX, pubKeyY: "0x" + pubKeyY };
};

export const signMessage = (message: string, privKeyHex: string) => {
  const key = ec.keyFromPrivate(privKeyHex, "hex");
  const hash = sha3_256(message);
  const signature = key.sign(hash);
  return {
    r: signature.r.toString("hex"),
    s: signature.s.toString("hex"),
  };
};

export const verifySignature = (
  message: string,
  r: string,
  s: string,
  pubX: string,
  pubY: string
) => {
  const key = ec.keyFromPublic({ x: pubX.replace("0x", ""), y: pubY.replace("0x", "") }, "hex");
  const hash = sha3_256(message);
  return key.verify(hash, { r, s });
};

export const hashMessage = (message: string) => sha3_256(message);
