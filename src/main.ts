// src/main.ts
import { Kyber } from './algorithms/kyber';

// Вспомогательная функция для преобразования байтов в шестнадцатеричную строку
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function demonstrateKyber() {
  console.log('Демонстрация работы постквантового алгоритма обмена ключами Kyber');
  
  try {
    // Шаг 1: Инициализация экземпляра Kyber
    const kyber = new Kyber();
    console.log('Kyber инициализирован');

    // Шаг 2: Генерация пары ключей (публичный и приватный ключи)
    console.log('\nГенерация пары ключей...');
    const aliceKeyPair = await kyber.generateKeyPair({ variant: Kyber.KYBER768 });
    console.log(`Публичный ключ (Alice): ${bytesToHex(aliceKeyPair.publicKey).substring(0, 64)}...`);
    console.log(`Приватный ключ (Alice): ${bytesToHex(aliceKeyPair.privateKey).substring(0, 64)}...`);

    // Шаг 3: Боб получает публичный ключ Алисы и выполняет инкапсуляцию
    console.log('\nИнкапсуляция (Bob использует публичный ключ Alice)...');
    const bobEncapsulation = await kyber.encapsulate(aliceKeyPair.publicKey, { variant: Kyber.KYBER768 });
    console.log(`Зашифрованный текст: ${bytesToHex(bobEncapsulation.ciphertext).substring(0, 64)}...`);
    console.log(`Общий секрет (Bob): ${bytesToHex(bobEncapsulation.sharedSecret).substring(0, 64)}...`);

    // Шаг 4: Алиса декапсулирует шифротекст с помощью своего приватного ключа
    console.log('\nДекапсуляция (Alice использует свой приватный ключ)...');
    const aliceSharedSecret = await kyber.decapsulate(
      bobEncapsulation.ciphertext,
      aliceKeyPair.privateKey,
      { variant: Kyber.KYBER768 }
    );
    console.log(`Общий секрет (Alice): ${bytesToHex(aliceSharedSecret).substring(0, 64)}...`);

    // Шаг 5: Проверка соответствия общих секретов
    const secretsMatch = compareUint8Arrays(bobEncapsulation.sharedSecret, aliceSharedSecret);
    console.log('\nРезультат:');
    console.log(`Общие секреты ${secretsMatch ? 'совпадают' : 'не совпадают'}!`);
    
    // Для демонстрации практического использования общего секрета
    if (secretsMatch) {
      console.log('\nПрактическое применение полученного общего секрета:');
      console.log('1. Использование для генерации ключей симметричного шифрования');
      console.log('2. Создание защищенного канала связи');
      console.log('3. Аутентификация сторон');
    }
    
  } catch (error) {
    console.error('Произошла ошибка:', error);
  }
}

// Вспомогательная функция для сравнения массивов Uint8Array
function compareUint8Arrays(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  
  return true;
}

// Запуск демонстрации
demonstrateKyber().catch(console.error);