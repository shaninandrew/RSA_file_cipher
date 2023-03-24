
﻿using System.Collections.Immutable;
using System.Data;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Diagnostics;

/* 
Программа шифрования файлов с помощью RSA
Шифрование проходит блоками по размеру переменной buffer
При расшифровании длина файла восстанавливается так как буфер выходного файла восстанавливается в исходную длину
т.к. в шифровке идет контроль исходных данных для 512 буфера шифро данных от 360 байт исходных данных - идут проблемы
 */

string in_file = "тестовый файл.txt";
string command = "-e"; // -e  шифровка /  -d расшифровка 
string key_file = "key.pem";

// Объект для работы с шифрованием
System.Security.Cryptography.RSACng cipher = new RSACng();


//если указали ключ-файл шифрования то внесем его в параметры
if (args.Length > 0)
{
    command = args[0]; // основная команда
    
    // позволяет расшифровывать  файлы сразу, если рядом лежит ключик key_file
    if (command.EndsWith(".rsa"))
    {
        in_file = args[0];
        command = "-d";
    }
    else
    {
        try { in_file = args[1]; } catch { }
        if (args.Length == 3) key_file = args[2];
    }
}


if ((command == "/?") || (command=="-?") || (command == "-help"))
        {
                Console.WriteLine("Справка:");
                Console.WriteLine("  -? /? -help ............................  вывод данной справки");
                Console.WriteLine("  -e file.txt     key.pem ................  шифрование файла file.txt с ключом в файле key.pem, на выходе файл .rsa ");
                Console.WriteLine("  -e file.txt     PUBLIC-KEY.pem .........  шифрование файла file.txt с публичным ключом в файле PUBLIC-KEY.pem, на выходе файл .rsa ");
                Console.WriteLine("  -d file.txt.rsa key.pem  ...............  расшифровка файла возможна только с помощью ЗАКРЫТОГО КЛЮЧА");
                Console.WriteLine("                                           ");
                Console.WriteLine("Из-за особенностей шифра RSA - размер выходного файла в 1.5 более оригинала");
                Console.WriteLine("                                           ");
                return;
        }

//Считываем в память ключевой файл
ReadOnlySpan<char> span_key_file = System.IO.File.ReadAllText(key_file);

// Грузим ключ в память
cipher.ImportFromPem(span_key_file);
Console.WriteLine("Ключ загружен! Размер ключа {0} бит", cipher.Key.KeySize);

//Размеры буферов
int ENCRYPT_LEN_BUFFER = cipher.Key.KeySize / 8;
int DECRYPT_LEN_BUFFER = cipher.Key.KeySize / 8;
int READ_LEN_BUFFER = (int) ((double)ENCRYPT_LEN_BUFFER / 3) * 2; // 2/3 от буфера шифрования
int ENCRYPTER_LEN_BUFFER = (int)((double)ENCRYPT_LEN_BUFFER / 3) * 2; // 2/3 от буфера шифрования

// ВЫХодной файл
string out_file = "";

//Считываем файл кусками
System.IO.BufferedStream sr = new System.IO.BufferedStream( System.IO.File.OpenRead(in_file));
System.IO.FileInfo fi = new FileInfo(in_file);
long SIZE_FILE = fi.Length / ENCRYPT_LEN_BUFFER; //кол-во блоков для считки
long DIVVER = SIZE_FILE / 1000 + 2; //делитель для прогресса


//буфер для загрузки
try { sr.ReadTimeout = 100; }   catch { }


   
// если передали имя файлв с .rsa то расшифровываем можно без -d
if ((in_file.EndsWith(".rsa")) || ((command == "-d") || (command == "/d")))
    {
    Console.WriteLine (" Расшифровка:  ");

    out_file = in_file.Replace(".rsa", "");
    System.IO.BufferedStream sw = new BufferedStream(System.IO.File.OpenWrite(out_file),DECRYPT_LEN_BUFFER*1000);

    Stopwatch timers_x = System.Diagnostics.Stopwatch.StartNew();
    //Расшифровка ...
    int i = 0;
    int read = 0;
    string decor_progress_bar = ".-=<__>*";
    int FLAG_READY = 0;
    do
    {

        byte[] read_buffer = new byte[DECRYPT_LEN_BUFFER * 100]; //условно 1k x 100
                                                                // сделаем большой буфер чтения

        int read_buffer_size = read_buffer.Length;

        read = sr.Read(read_buffer, 0, read_buffer_size);
        if (read == 0) { break; }

        //кол-во блоков которые можно зашифровать и пишем потом, а считываем большим куском (2/3 размера ключа)
        int blocks = read / DECRYPT_LEN_BUFFER + 1;
        int last_block = read % DECRYPT_LEN_BUFFER; //по идее 0
        //при дешефровке файл весь из кусоков размером с ключ шифрования
        if (last_block == 0) { last_block = DECRYPT_LEN_BUFFER;  }
        
        //Индекс кусочка буфера
        int x = 0;
        int LEN = DECRYPT_LEN_BUFFER;

        Stopwatch action_time = Stopwatch.StartNew();


        //ПРОСТО КУСОК БУФЕРОВ
        // Так как писать медленно - то просто добавляем все штабля, и вывозим на 1 барже
        List< byte[] > out_buffer = new List<byte[]  >();
        out_buffer.Clear();

        //Попробуем отмногопотчить
        // скорость дешифрвания - 25 кб/с - мало
        // сделаем многопоток

        int RUN_THREADS = 0;
        do
        {
            //Размер кусочка по длине подходящего для шифрования
            if (x == blocks - 1)
            {
                LEN = 0;
                break; //?
            } //последний блок

            //массив кусков которые можно шифровать
            
            
            out_buffer.Add(null); // добавляем в лист - пустой массив


            int Index = out_buffer.Count - 1;
            //подрезаем массив на длину в реальности (если буфер менее его размера)

            ReadOnlySpan<byte> chunkie = read_buffer.AsSpan(x * DECRYPT_LEN_BUFFER, LEN); // самая тяжелая часть

            //К сожалению нужно делать копию
            int chunkie_len = chunkie.Length;

            //просто так в потоке дернуть копию нельзя...
            byte[] chunkie_copy = new byte[chunkie_len];
            chunkie.CopyTo(chunkie_copy);

            // запишим в пром буфер
            ParameterizedThreadStart tz = new ParameterizedThreadStart(delegate {
                
                int i = Index+0; // копирование в новую ячейку
                int copy_x = x + 0;
                byte[] chunkie_copy2 = chunkie_copy.ToArray<byte>();

                try
                {
                    byte[] decrypted_buffer = cipher.Decrypt(chunkie_copy2, RSAEncryptionPadding.OaepSHA1); // самая тяжелая часть
                    out_buffer[i] = decrypted_buffer;
                }
                finally
                {
                    //флаги поднять - что готово
                    FLAG_READY = FLAG_READY + 1;
                    RUN_THREADS--;
                }

            });

            Thread thread = new Thread(tz);
            thread.Start();
            i++;
            x++;
            RUN_THREADS++;

        } while (x < blocks);

        //теперь вопрос КАК ПРОВЕРИТЬ ЧТО ДАННЫЕ ГОТОВЫ ? Мониторим

        do
        {
            Thread.Sleep(100); // ждем пока все не выполнят
            Console.Write(".");
        } while (FLAG_READY < RUN_THREADS);

            action_time.Stop();

        try
        {
            //для ускорения показа процесса   не важно если тут ошибка - важно файл скинуть
            double process_action = (double)i * 100 / (SIZE_FILE )+0.001; // %

            long elapsed = (long) ((double)timers_x.ElapsedMilliseconds / ( process_action/100 + 0.0001) - timers_x.ElapsedMilliseconds) / 1000;
            double speed = ((double)read_buffer_size / ((double)action_time.ElapsedMilliseconds / 1000))/1000;
            Console.Write("\r {0} x {1} байт -  {2:N} %  - - осталось {3} сек  - - цикл расшифровки {4:N} Кбайт/сек  \r  ", i, read, process_action, elapsed, speed);
        }
        catch 
        { }

        // баржа
        foreach (byte[] chunk in out_buffer)
        {
           if ( chunk !=null)
            try
            {
                sw.WriteAsync(chunk, 0, chunk.Length); // 40 ms
            }
            catch { }
         }

        out_buffer.Clear(); //очистка
        //GC.Collect();
      
        if (read == 0) { break; }

    } while (true); // while
    


    Console.WriteLine("");

    Console.WriteLine("Время операции рашифрования {0} мин. ", timers_x.Elapsed.Minutes);
    timers_x.Stop();

    Console.WriteLine(" ФАйл записан.  ");
    sw.Close();
    Console.WriteLine("Файл расшифрован: {0} ", out_file);
    }
else
if ((!in_file.EndsWith(".rsa")) && ( (command == "-e") || (command == "/e")))
    {
        //выходной архив
        out_file = in_file + ".rsa";
        int i = 0;

        // размер файла
        SIZE_FILE = fi.Length / ENCRYPTER_LEN_BUFFER;

        System.IO.BufferedStream sw = new BufferedStream(System.IO.File.OpenWrite(out_file));
        Console.WriteLine("Читаем кусками по {0} КБ", ENCRYPT_LEN_BUFFER );
        
        Stopwatch timers_x=  System.Diagnostics.Stopwatch.StartNew();
        

        int read = 0;
        do
        {

            byte[] read_buffer = new byte[ENCRYPT_LEN_BUFFER * 1000]; //условно 1k x 1000
            // сделаем большой буфер чтения
            read = sr.Read(read_buffer, 0, read_buffer.Length);
            if (read == 0) { break; }

            //кол-во блоков которые можно зашифровать и пишем потом, а считываем большим куском (2/3 размера ключа)
            int blocks = read / ENCRYPTER_LEN_BUFFER + 1;
            int last_block = read % ENCRYPTER_LEN_BUFFER;

            int x = 0;

            do
            {

                //Размер кусочка по длине подходящего для шифрования
                int LEN = ENCRYPTER_LEN_BUFFER;
                if (x == blocks - 1)
                { LEN = last_block; } //последний блок
                
                //массив кусков которые можно шифровать
                ReadOnlySpan<byte> chunkie = read_buffer.AsSpan(x * ENCRYPTER_LEN_BUFFER, LEN);
                x++;

                //подрезаем массив на длину в реальности (если буфер менее его размера)
                byte[] encrypted_buffer = cipher.Encrypt(chunkie , RSAEncryptionPadding.OaepSHA1);

                // запишим
                sw.Write(encrypted_buffer, 0, encrypted_buffer.Length);

            //для ускорения показа
            if (i % (DIVVER) == 1) { Console.Write("\b \r {0} x {1} -  {2}% ", i, read, (int)((double)i * 100 / SIZE_FILE)); }
            i++;

        } while (x < blocks);

       // GC.Collect();

        if (read == 0) { break;  }

    } while (true);

    timers_x.Stop();
    //закрываем потоки
    sw.Close();
    Console.WriteLine("");
    Console.WriteLine("Время операции шифрования {0} мин. ", timers_x.Elapsed.Minutes);
    Console.WriteLine("");
    Console.WriteLine("Файл зашифрован: {0} ", out_file);
    }
//закрываем считку
sr.Close();



=======
﻿using System.Collections.Immutable;
using System.Data;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Diagnostics;

/* 
Программа шифрования файлов с помощью RSA
Шифрование проходит блоками по размеру переменной buffer
При расшифровании длина файла восстанавливается так как буфер выходного файла восстанавливается в исходную длину
т.к. в шифровке идет контроль исходных данных для 512 буфера шифро данных от 360 байт исходных данных - идут проблемы
 */

string in_file = "тестовый файл.txt";
string command = "-e"; // -e  шифровка /  -d расшифровка 
string key_file = "key.pem";

// Объект для работы с шифрованием
System.Security.Cryptography.RSACng cipher = new RSACng();


//если указали ключ-файл шифрования то внесем его в параметры
if (args.Length > 0)
{
    command = args[0]; // основная команда
    
    // позволяет расшифровывать  файлы сразу, если рядом лежит ключик key_file
    if (command.EndsWith(".rsa"))
    {
        in_file = args[0];
        command = "-d";
    }
    else
    {
        try { in_file = args[1]; } catch { }
        if (args.Length == 3) key_file = args[2];
    }
}


if ((command == "/?") || (command=="-?") || (command == "-help"))
        {
                Console.WriteLine("Справка:");
                Console.WriteLine("  -? /? -help ............................  вывод данной справки");
                Console.WriteLine("  -e file.txt     key.pem ................  шифрование файла file.txt с ключом в файле key.pem, на выходе файл .rsa ");
                Console.WriteLine("  -e file.txt     PUBLIC-KEY.pem .........  шифрование файла file.txt с публичным ключом в файле PUBLIC-KEY.pem, на выходе файл .rsa ");
                Console.WriteLine("  -d file.txt.rsa key.pem  ...............  расшифровка файла возможна только с помощью ЗАКРЫТОГО КЛЮЧА");
                Console.WriteLine("                                           ");
                Console.WriteLine("Из-за особенностей шифра RSA - размер выходного файла в 1.5 более оригинала");
                Console.WriteLine("                                           ");
                return;
        }

//Считываем в память ключевой файл
ReadOnlySpan<char> span_key_file = System.IO.File.ReadAllText(key_file);

// Грузим ключ в память
cipher.ImportFromPem(span_key_file);
Console.WriteLine("Ключ загружен! Размер ключа {0} бит", cipher.Key.KeySize);

//Размеры буферов
int ENCRYPT_LEN_BUFFER = cipher.Key.KeySize / 8;
int DECRYPT_LEN_BUFFER = cipher.Key.KeySize / 8;
int READ_LEN_BUFFER = (int) ((double)ENCRYPT_LEN_BUFFER / 3) * 2; // 2/3 от буфера шифрования
int ENCRYPTER_LEN_BUFFER = (int)((double)ENCRYPT_LEN_BUFFER / 3) * 2; // 2/3 от буфера шифрования

// ВЫХодной файл
string out_file = "";

//Считываем файл кусками
System.IO.BufferedStream sr = new System.IO.BufferedStream( System.IO.File.OpenRead(in_file));
System.IO.FileInfo fi = new FileInfo(in_file);
long SIZE_FILE = fi.Length / ENCRYPT_LEN_BUFFER; //кол-во блоков для считки
long DIVVER = SIZE_FILE / 1000 + 2; //делитель для прогресса


//буфер для загрузки
try { sr.ReadTimeout = 100; }   catch { }


   
// если передали имя файлв с .rsa то расшифровываем можно без -d
if ((in_file.EndsWith(".rsa")) || ((command == "-d") || (command == "/d")))
    {
    Console.WriteLine (" Расшифровка:  ");

    out_file = in_file.Replace(".rsa", "");
    System.IO.BufferedStream sw = new BufferedStream(System.IO.File.OpenWrite(out_file),DECRYPT_LEN_BUFFER*1000);

    Stopwatch timers_x = System.Diagnostics.Stopwatch.StartNew();
    //Расшифровка ...
    int i = 0;
    int read = 0;
    string decor_progress_bar = ".-=<__>*";
    int FLAG_READY = 0;
    do
    {

        byte[] read_buffer = new byte[DECRYPT_LEN_BUFFER * 100]; //условно 1k x 100
                                                                // сделаем большой буфер чтения

        int read_buffer_size = read_buffer.Length;

        read = sr.Read(read_buffer, 0, read_buffer_size);
        if (read == 0) { break; }

        //кол-во блоков которые можно зашифровать и пишем потом, а считываем большим куском (2/3 размера ключа)
        int blocks = read / DECRYPT_LEN_BUFFER + 1;
        int last_block = read % DECRYPT_LEN_BUFFER; //по идее 0
        //при дешефровке файл весь из кусоков размером с ключ шифрования
        if (last_block == 0) { last_block = DECRYPT_LEN_BUFFER;  }
        
        //Индекс кусочка буфера
        int x = 0;
        int LEN = DECRYPT_LEN_BUFFER;

        Stopwatch action_time = Stopwatch.StartNew();


        //ПРОСТО КУСОК БУФЕРОВ
        // Так как писать медленно - то просто добавляем все штабля, и вывозим на 1 барже
        List< byte[] > out_buffer = new List<byte[]  >();
        out_buffer.Clear();

        //Попробуем отмногопотчить
        // скорость дешифрвания - 25 кб/с - мало
        // сделаем многопоток

        int RUN_THREADS = 0;
        do
        {
            //Размер кусочка по длине подходящего для шифрования
            if (x == blocks - 1)
            {
                LEN = 0;
                break; //?
            } //последний блок

            //массив кусков которые можно шифровать
            
            
            out_buffer.Add(null); // добавляем в лист - пустой массив


            int Index = out_buffer.Count - 1;
            //подрезаем массив на длину в реальности (если буфер менее его размера)

            ReadOnlySpan<byte> chunkie = read_buffer.AsSpan(x * DECRYPT_LEN_BUFFER, LEN); // самая тяжелая часть

            //К сожалению нужно делать копию
            int chunkie_len = chunkie.Length;

            //просто так в потоке дернуть копию нельзя...
            byte[] chunkie_copy = new byte[chunkie_len];
            chunkie.CopyTo(chunkie_copy);

            // запишим в пром буфер
            ParameterizedThreadStart tz = new ParameterizedThreadStart(delegate {
                
                int i = Index+0; // копирование в новую ячейку
                int copy_x = x + 0;
                byte[] chunkie_copy2 = chunkie_copy.ToArray<byte>();

                try
                {
                    byte[] decrypted_buffer = cipher.Decrypt(chunkie_copy2, RSAEncryptionPadding.OaepSHA1); // самая тяжелая часть
                    out_buffer[i] = decrypted_buffer;
                }
                finally
                {
                    //флаги поднять - что готово
                    FLAG_READY = FLAG_READY + 1;
                    RUN_THREADS--;
                }

            });

            Thread thread = new Thread(tz);
            thread.Start();
            i++;
            x++;
            RUN_THREADS++;

        } while (x < blocks);

        //теперь вопрос КАК ПРОВЕРИТЬ ЧТО ДАННЫЕ ГОТОВЫ ? Мониторим

        do
        {
            Thread.Sleep(100); // ждем пока все не выполнят
            Console.Write(".");
        } while (FLAG_READY < RUN_THREADS);

            action_time.Stop();

        try
        {
            //для ускорения показа процесса   не важно если тут ошибка - важно файл скинуть
            double process_action = (double)i * 100 / (SIZE_FILE )+0.001; // %

            long elapsed = (long) ((double)timers_x.ElapsedMilliseconds / ( process_action/100 + 0.0001) - timers_x.ElapsedMilliseconds) / 1000;
            double speed = ((double)read_buffer_size / ((double)action_time.ElapsedMilliseconds / 1000))/1000;
            Console.Write("\r {0} x {1} байт -  {2:N} %  - - осталось {3} сек  - - цикл расшифровки {4:N} Кбайт/сек  \r  ", i, read, process_action, elapsed, speed);
        }
        catch 
        { }

        // баржа
        foreach (byte[] chunk in out_buffer)
        {
           if ( chunk !=null)
            try
            {
                sw.WriteAsync(chunk, 0, chunk.Length); // 40 ms
            }
            catch { }
         }

        out_buffer.Clear(); //очистка
        //GC.Collect();
      
        if (read == 0) { break; }

    } while (true); // while
    


    Console.WriteLine("");

    Console.WriteLine("Время операции рашифрования {0} мин. ", timers_x.Elapsed.Minutes);
    timers_x.Stop();

    Console.WriteLine(" ФАйл записан.  ");
    sw.Close();
    Console.WriteLine("Файл расшифрован: {0} ", out_file);
    }
else
if ((!in_file.EndsWith(".rsa")) && ( (command == "-e") || (command == "/e")))
    {
        //выходной архив
        out_file = in_file + ".rsa";
        int i = 0;

        // размер файла
        SIZE_FILE = fi.Length / ENCRYPTER_LEN_BUFFER;

        System.IO.BufferedStream sw = new BufferedStream(System.IO.File.OpenWrite(out_file));
        Console.WriteLine("Читаем кусками по {0} КБ", ENCRYPT_LEN_BUFFER );
        
        Stopwatch timers_x=  System.Diagnostics.Stopwatch.StartNew();
        

        int read = 0;
        do
        {

            byte[] read_buffer = new byte[ENCRYPT_LEN_BUFFER * 1000]; //условно 1k x 1000
            // сделаем большой буфер чтения
            read = sr.Read(read_buffer, 0, read_buffer.Length);
            if (read == 0) { break; }

            //кол-во блоков которые можно зашифровать и пишем потом, а считываем большим куском (2/3 размера ключа)
            int blocks = read / ENCRYPTER_LEN_BUFFER + 1;
            int last_block = read % ENCRYPTER_LEN_BUFFER;

            int x = 0;

            do
            {

                //Размер кусочка по длине подходящего для шифрования
                int LEN = ENCRYPTER_LEN_BUFFER;
                if (x == blocks - 1)
                { LEN = last_block; } //последний блок
                
                //массив кусков которые можно шифровать
                ReadOnlySpan<byte> chunkie = read_buffer.AsSpan(x * ENCRYPTER_LEN_BUFFER, LEN);
                x++;

                //подрезаем массив на длину в реальности (если буфер менее его размера)
                byte[] encrypted_buffer = cipher.Encrypt(chunkie , RSAEncryptionPadding.OaepSHA1);

                // запишим
                sw.Write(encrypted_buffer, 0, encrypted_buffer.Length);

            //для ускорения показа
            if (i % (DIVVER) == 1) { Console.Write("\b \r {0} x {1} -  {2}% ", i, read, (int)((double)i * 100 / SIZE_FILE)); }
            i++;

        } while (x < blocks);

       // GC.Collect();

        if (read == 0) { break;  }

    } while (true);

    timers_x.Stop();
    //закрываем потоки
    sw.Close();
    Console.WriteLine("");
    Console.WriteLine("Время операции шифрования {0} мин. ", timers_x.Elapsed.Minutes);
    Console.WriteLine("");
    Console.WriteLine("Файл зашифрован: {0} ", out_file);
    }
//закрываем считку
sr.Close();

