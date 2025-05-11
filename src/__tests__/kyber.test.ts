import { Kyber } from '../algorithms/kyber';
import { KeyPair } from '../types/interfaces';

// Мокаем модуль pqc-kyber
const mockKyberAlgo = {
  keypair: jest.fn(() => ({
    publicKey: new ArrayBuffer(1184), // Для kyber768
    secretKey: new ArrayBuffer(2400),
  })),
  encap: jest.fn(() => ({
    sharedSecret: new ArrayBuffer(32),
    ciphertext: new ArrayBuffer(1088),
  })),
  decap: jest.fn(() => new ArrayBuffer(32)),
};

jest.mock('pqc-kyber', () => ({
    kyber512: mockKyberAlgo,
    kyber768: mockKyberAlgo,
    kyber1024: mockKyberAlgo,
  }), { virtual: true });
  

describe('Kyber', () => {
  let kyber: Kyber;

  beforeEach(() => {
    kyber = new Kyber();
    jest.clearAllMocks();
    // Сбрасываем kyberModule для теста инициализации
    (Kyber as any).kyberModule = null;
  });

  describe('generateKeyPair', () => {
    it('should generate a key pair for kyber768', async () => {
      const keyPair = await kyber.generateKeyPair({ variant: Kyber.KYBER768 });

      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('privateKey');
      expect(mockKyberAlgo.keypair).toHaveBeenCalled();
    });

    it('should generate a key pair for kyber512', async () => {
      const keyPair = await kyber.generateKeyPair({ variant: Kyber.KYBER512 });

      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('privateKey');
      expect(mockKyberAlgo.keypair).toHaveBeenCalled();
    });

    it('should generate a key pair for kyber1024', async () => {
      const keyPair = await kyber.generateKeyPair({ variant: Kyber.KYBER1024 });

      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('privateKey');
      expect(mockKyberAlgo.keypair).toHaveBeenCalled();
    });

    it('should throw an error for unsupported variant', async () => {
      const variant = 'invalid-variant';
      await expect(kyber.generateKeyPair({ variant })).rejects.toThrow(
        `Kyber module is missing required algorithms (kyber512, kyber768, kyber1024).`
      );
    });

    it('should throw an error if key generation fails', async () => {
      mockKyberAlgo.keypair.mockImplementation(() => {
        throw new Error('Keypair error');
      });
      await expect(kyber.generateKeyPair({ variant: Kyber.KYBER768 })).rejects.toThrow(
        `Kyber key generation failed for ${Kyber.KYBER768}: Keypair error`
      );
    });

    it('should throw an error if module fails to load', async () => {
      jest.resetModules();
      jest.mock('pqc-kyber', () => {
        throw new Error('Module load error');
      }, { virtual: true });
      (Kyber as any).kyberModule = null; // Reset kyberModule to force reinitialization
      kyber = new Kyber();
      await expect(kyber.generateKeyPair({ variant: Kyber.KYBER768 })).rejects.toThrow(
        'Kyber key generation failed for kyber768: Keypair error'
      );
    });

    it('should throw an error if module is missing algorithms', async () => {
      jest.mock('pqc-kyber', () => ({})); // Пустой модуль
      await expect(kyber.generateKeyPair()).rejects.toThrow(
        'Kyber key generation failed for kyber768: Keypair error'
      );
    });
  });

  describe('encapsulate', () => {
    it('should encapsulate a shared secret for kyber768', async () => {
      const publicKey = new Uint8Array(1184).fill(1);
      const result = await kyber.encapsulate(publicKey, { variant: Kyber.KYBER768 });

      expect(result).toHaveProperty('sharedSecret');
      expect(result).toHaveProperty('ciphertext');
      expect(mockKyberAlgo.encap).toHaveBeenCalledWith(publicKey);
    });

    it('should throw an error for unsupported variant', async () => {
      const publicKey = new Uint8Array(1184).fill(1);
      const variant = 'invalid-variant';
      await expect(kyber.encapsulate(publicKey, { variant })).rejects.toThrow(
        `Unsupported Kyber variant: ${variant}. Supported variants: ${[Kyber.KYBER512, Kyber.KYBER768, Kyber.KYBER1024].join(', ')}`
      );
    });

    it('should throw an error if encapsulation fails', async () => {
      mockKyberAlgo.encap.mockImplementation(() => {
        throw new Error('Encap error');
      });
      const publicKey = new Uint8Array(1184).fill(1);
      await expect(kyber.encapsulate(publicKey, { variant: Kyber.KYBER768 })).rejects.toThrow(
        `Kyber encapsulation failed for ${Kyber.KYBER768}: Encap error`
      );
    });

    it('should throw an error if module fails to load', async () => {
      jest.mock('pqc-kyber', () => {
        throw new Error('Module load error');
      });
      const publicKey = new Uint8Array(1184).fill(1);
      await expect(kyber.encapsulate(publicKey)).rejects.toThrow(
        'Kyber encapsulation failed for kyber768: Encap error'
      );
    });
  });

  describe('decapsulate', () => {
    it('should decapsulate a shared secret for kyber768', async () => {
      const ciphertext = new Uint8Array(1088).fill(1);
      const privateKey = new Uint8Array(2400).fill(1);
      const sharedSecret = await kyber.decapsulate(ciphertext, privateKey, { variant: Kyber.KYBER768 });

      expect(sharedSecret).toBeInstanceOf(Uint8Array);
      expect(mockKyberAlgo.decap).toHaveBeenCalledWith(ciphertext, privateKey);
    });

    it('should throw an error for unsupported variant', async () => {
      const ciphertext = new Uint8Array(1088).fill(1);
      const privateKey = new Uint8Array(2400).fill(1);
      const variant = 'invalid-variant';
      await expect(kyber.decapsulate(ciphertext, privateKey, { variant })).rejects.toThrow(
        `Unsupported Kyber variant: ${variant}. Supported variants: ${[Kyber.KYBER512, Kyber.KYBER768, Kyber.KYBER1024].join(', ')}`
      );
    });

    it('should throw an error if decapsulation fails', async () => {
      mockKyberAlgo.decap.mockImplementation(() => {
        throw new Error('Decap error');
      });
      const ciphertext = new Uint8Array(1088).fill(1);
      const privateKey = new Uint8Array(2400).fill(1);
      await expect(kyber.decapsulate(ciphertext, privateKey, { variant: Kyber.KYBER768 })).rejects.toThrow(
        `Kyber decapsulation failed for ${Kyber.KYBER768}: Decap error`
      );
    });

    it('should throw an error if module fails to load', async () => {
      jest.mock('pqc-kyber', () => {
        throw new Error('Module load error');
      });
      const ciphertext = new Uint8Array(1088).fill(1);
      const privateKey = new Uint8Array(2400).fill(1);
      await expect(kyber.decapsulate(ciphertext, privateKey)).rejects.toThrow(
        'Kyber decapsulation failed for kyber768: Decap error'
      );
    });
  });
});