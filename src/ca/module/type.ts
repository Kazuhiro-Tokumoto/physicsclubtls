export type clienthello = {
  type: "clienthello";
  version: number;
  pubkey: string;
};
export type serverhello = {
  type: "serverhello";
  version: number;
  pubkey: string;
  certificate: any[][];
};
export type SendMessage =
  | {
      type: "message";
      // message の時は filename を持たせない（ミスを防ぐ）
      ciphertext: string;
    }
  | {
      type: "file";
      // file の時は filename を必須にする（送り忘れを防ぐ）
      number: number;
      fileid: string;
      filename: string;
      ciphertext: string;
    };
export type ping = {
  type: "ping";
};
export type pong = {
  type: "pong";
};
export type ACK = {
  type: "ACK";
};
