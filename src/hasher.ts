import { randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';

const DEFAULT_SALT_LENGTH = 8;
const DEFAULT_HASH_LENGTH = 16;
const DELIMITER_SALT = '.';
const DELIMITER_LENGTH_SALT = '#';

/**
 * Generates a random salt of the specified length.
 *
 * @param len - The desired length of the salt in bytes. The actual length of the
 *              returned string will be twice this value (since it's hex-encoded).
 *              Defaults to 4.
 * @returns A hexadecimal string representing the salt.
 * @throws Error if the provided length is not a positive integer.
 */
export const getSalt = (len = DEFAULT_SALT_LENGTH): string => {
  if (!Number.isInteger(len) || len <= 0) {
    throw new Error('Length must be a positive integer.');
  }
  const byteLength = Math.max(Math.floor(len / 2), 1);
  return randomBytes(byteLength).toString('hex');
};

/**
 * Hashes a password with a generated salt.
 *
 * @param password - The password to be hashed. Must be a non-empty string.
 * @param salt - The salt to use for hashing. If not provided, a new salt will be generated.
 * @param len - The length of the derived key. Defaults to 32 bytes.
 * @returns A promise that resolves to the hashed password in the format "salt.hash".
 * @throws Error if the password is empty, invalid, or if hashing fails.
 */
export const getHashedPassword = async (
  password: string,
  salt = getSalt(DEFAULT_SALT_LENGTH),
  len = DEFAULT_HASH_LENGTH
) => {
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a non-empty string.');
  }

  if (!salt || typeof salt !== 'string') {
    throw new Error('Salt must be a non-empty string.');
  }

  if (!Number.isInteger(len) || len <= 0) {
    throw new Error('Length must be a positive integer.');
  }

  try {
    const ncrypt = promisify(scrypt);
    const hash = (await ncrypt(password, salt, len)) as Buffer;
    return `${len}#${salt}.${hash.toString('hex')}`;
  } catch (error) {
    throw new Error('Error hashing password: ' + error);
  }
};

/**
 * Verifies a password against a hashed password.
 *
 * @param password - The plain text password to verify.
 * @param hashPassword - The hashed password to compare against.
 * @returns A promise that resolves to a boolean indicating whether the password is valid.
 * @throws Error if the hashPassword format is invalid.
 */
export const verifyHash = async (password: string, hashPassword: string) => {
  const [saltInfo, hashedValue] = hashPassword.split(DELIMITER_SALT);
  if (!saltInfo || !hashedValue) {
    throw new Error('Invalid hashPassword format.');
  }
  const [lengthString, salt] = saltInfo.split(DELIMITER_LENGTH_SALT);
  const len = Number(lengthString);

  if (isNaN(len) || len <= 0) {
    throw new Error('Invalid hashPassword format.');
  }
  const newHashPassword = await getHashedPassword(password, salt, len);
  return hashPassword === newHashPassword;
};

export const generateStrongPassword = (length = 12): string => {
  const uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
  const numberChars = '0123456789';
  const symbolChars = '!@#$%^&*()_+=-`~[]\\{}|;\':",./<>?';

  const allChars = uppercaseChars + lowercaseChars + numberChars + symbolChars;
  const allCharsLength = allChars.length;

  if (length < 8) {
    throw new Error('Password length must be at least 8 characters.');
  }

  let password = '';
  const has: { [key: string]: boolean } = {
    uppercase: false,
    lowercase: false,
    number: false,
    symbol: false,
  };

  // Ensure at least one character from each set
  password += uppercaseChars.charAt(
    Math.floor(Math.random() * uppercaseChars.length)
  );
  has['uppercase'] = true;
  password += lowercaseChars.charAt(
    Math.floor(Math.random() * lowercaseChars.length)
  );
  has['lowercase'] = true;
  password += numberChars.charAt(
    Math.floor(Math.random() * numberChars.length)
  );
  has['number'] = true;
  password += symbolChars.charAt(
    Math.floor(Math.random() * symbolChars.length)
  );
  has['symbol'] = true;

  // Fill the remaining length with random characters
  for (let i = password.length; i < length; i++) {
    password += allChars.charAt(Math.floor(Math.random() * allCharsLength));
  }

  // Shuffle the password to make it more random
  const shuffledPassword = password
    .split('')
    .sort(() => Math.random() - 0.5)
    .join('');

  return shuffledPassword;
};
