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
        fingerprint: bigInt('8296516683022330338'),
        n: bigInt(
            '2812355715883442641223900852404427642853454295085323516785839742669932962688092840046591109564876670891'
            + '8267359603153797193048813155878093009690030674331616458275800676547955484408991390100541484823412050597'
            + '4671599902678658161014085601148877714352978771910751777470769106792524427913145346390609539255717086774'
            + '4221517753564563575594760827748586931186846327944678230981940001287612938724358750075431587106402955732'
            + '8659655835792774995620173266238058217377518923295302990457388937333571970114784303618197073958650795903'
            + '157822391651419355231703019590257287406430927767664151359061332502123509828550244079900901134972485915',
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
