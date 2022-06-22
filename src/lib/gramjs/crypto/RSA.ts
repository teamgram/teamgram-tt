import bigInt from 'big-integer';
import {
    generateRandomBytes,
    modExp,
    readBigIntFromBuffer,
    readBufferFromBigInt,
    sha1,
} from '../Helpers';

export const SERVER_KEYS = [
    {
        fingerprint: bigInt('-6205835210776354611'),
        n: bigInt(
            '2381306448659649164302690303076381265632668704723497020470395109308660514362364170229081106692857621740'
            + '7662304029739903180202186741388339194122731428033163392461508934209366018606125548366054726592597621897'
            + '3082720149482025777155599562826488748588535295468401288090233825534456644976428692936545848200589727693'
            + '5210354467286312442332644832723879423343018224783552507234685708030057684494633385257705768861429070097'
            + '9666942677163711643994719528044002167040190181767491250722153710492547051038733909766620291079011906347'
            + '813649336894843319316782175618810042958656414976948048313098163484344821927424378043409879056691914519',
        ),
        e: 65537,
    },
].reduce((acc, { fingerprint, ...keyInfo }) => {
    acc.set(fingerprint.toString(), keyInfo);
    return acc;
}, new Map<string, { n: bigInt.BigInteger; e: number }>());

/**
 * Encrypts the given data known the fingerprint to be used
 * in the way Telegram requires us to do so (sha1(data) + data + padding)

 * @param fingerprint the fingerprint of the RSA key.
 * @param data the data to be encrypted.
 * @returns {Buffer|*|undefined} the cipher text, or undefined if no key matching this fingerprint is found.
 */
export async function encrypt(fingerprint: bigInt.BigInteger, data: Buffer) {
    const key = SERVER_KEYS.get(fingerprint.toString());
    if (!key) {
        return undefined;
    }

    // len(sha1.digest) is always 20, so we're left with 255 - 20 - x padding
    const rand = generateRandomBytes(235 - data.length);

    const toEncrypt = Buffer.concat([await sha1(data), data, rand]);

    // rsa module rsa.encrypt adds 11 bits for padding which we don't want
    // rsa module uses rsa.transform.bytes2int(to_encrypt), easier way:
    const payload = readBigIntFromBuffer(toEncrypt, false);
    const encrypted = modExp(payload, bigInt(key.e), key.n);
    // rsa module uses transform.int2bytes(encrypted, keylength), easier:
    return readBufferFromBigInt(encrypted, 256, false);
}
