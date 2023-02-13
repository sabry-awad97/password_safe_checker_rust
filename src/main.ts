import axios from 'axios';
import * as crypto from 'crypto';

type PasswordCheckStatus =
  | {
      type: 'Compromised';
      count: number;
    }
  | {
      type: 'Safe';
    };

interface PasswordCheckResult {
  password: string;
  status: PasswordCheckStatus;
}

class API {
  private client = axios;

  async getPasswordLeaks(queryChar: string): Promise<string> {
    const url = `https://api.pwnedpasswords.com/range/${queryChar}`;
    const response = await this.client.get<string>(url);
    return response.data;
  }
}

class PasswordHasher {
  private sha1 = crypto.createHash('sha1');

  hashPassword(password: string): string {
    this.sha1.update(password);
    return this.sha1.digest('hex').toUpperCase();
  }
}

function getPasswordStatus(
  apiResponse: string,
  hashToCheck: string
): PasswordCheckStatus {
  const lines = apiResponse.split('\n');
  const hashCounts: { [hash: string]: number } = {};
  for (const line of lines) {
    const parts = line.split(':');
    hashCounts[parts[0]] = parseInt(parts[1], 10);
  }
  if (hashCounts[hashToCheck]) {
    return { type: 'Compromised', count: hashCounts[hashToCheck] };
  } else {
    return { type: 'Safe' };
  }
}

async function checkPassword(
  api: API,
  password: string
): Promise<PasswordCheckResult> {
  const passwordHasher = new PasswordHasher();
  const sha1Password = passwordHasher.hashPassword(password);
  const first5Chars = sha1Password.substring(0, 5);
  const tail = sha1Password.substring(5);
  const apiResponse = await api.getPasswordLeaks(first5Chars);
  return { password, status: getPasswordStatus(apiResponse, tail) };
}

async function main() {
  const api = new API();
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log(
      'Please provide at least one password as a command-line argument.'
    );
    return;
  }
  const passwordChecks = args.map(async password => {
    return await checkPassword(api, password);
  });
  const results = await Promise.all(passwordChecks);
  for (const result of results) {
    switch (result.status.type) {
      case 'Compromised':
        console.log(
          `The password: ${result.password} has been compromised ${result.status.count} times! Consider changing it.`
        );
        break;
      case 'Safe':
        console.log(`The password: ${result.password} is safe!`);
        break;
    }
  }
}

main();
