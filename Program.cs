using System.Collections.Immutable;
using System.Data;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

/* 
Программа шифрования файлов с помощью RSA
Шифрование проходит блоками по размеру переменной buffer
При расшифровании длина файла восстанавливается так как буфер выходного файла восстанавливается в исходную длину
т.к. в шифровке идет контроль исходных данных для 512 буфера шифро данных от 360 байт исходных данных - идут проблемы
 */

string in_file = "тестовый файл.txt";
string command = "-e"; // -e  шифровка /  -d расшифровка 
string key_file = "pub-key.pem";

// Объект для работы с шифрованием

RSAParameters params_r = new RSAParameters();
System.Security.Cryptography.RSACng cipher = new RSACng();


//если указали ключ-файл шифрования то внесем его в параметры
if (args.Length > 0)
{
    command = args[0]; // основная команда

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
int READ_LEN_BUFFER = (int) ((double)ENCRYPT_LEN_BUFFER / 3) * 2; // 2/3 от буфера шифрования



// ВЫХодной файл
string out_file = "";

//Размер буфера файла, который будет кусочками шифроваться
byte[] buffer = new byte[READ_LEN_BUFFER];

//Считываем файл кусками
System.IO.BufferedStream sr = new System.IO.BufferedStream( System.IO.File.OpenRead(in_file) ,buffer.Length);
System.IO.FileInfo fi = new FileInfo(in_file);
long SIZE_FILE = fi.Length / ENCRYPT_LEN_BUFFER; //кол-во блоков для считки

long DIVVER = SIZE_FILE / 1000 + 2; //делитель для прогресса


//буфер для загрузки
try { sr.ReadTimeout = 100; }   catch { }


   
// если передали имя файлв с .rsa то расшифровываем можно без -d
if ((in_file.EndsWith(".rsa")) || ((command == "-d") || (command == "/d")))
    {
        Console.Write(" Расшифровка:  ");

        out_file = in_file.Replace(".rsa", "");
        byte[] decrypt_buffer = new byte[ENCRYPT_LEN_BUFFER];
        System.IO.BufferedStream sw = new BufferedStream(System.IO.File.OpenWrite(out_file), decrypt_buffer.Length);
        int read = 0;
        int i = 1;
        do
        {
            read = sr.Read(decrypt_buffer, 0, decrypt_buffer.Length);
            if (read == 0) { break; }

            //подрезаем массив на длину в реальности (если буфер менее его размера)
            ReadOnlySpan<byte> iobuffer = decrypt_buffer.AsSpan(0, read);
            try
            {
                buffer = cipher.Decrypt(iobuffer, RSAEncryptionPadding.OaepSHA1);
                //для ускорения  вывода на экран
                if (i % (DIVVER) == 1) { Console.Write("\b \r {0} x {1} -  {2}% ", i, read, (int)((double)i *100 / SIZE_FILE) ); }
                 i++;
            }
            catch  (Exception ex)
            {
                Console.WriteLine("Ошибка при расшифровке файла: {0}", ex.Message);
                break;
            }

            //Пишем в выходной файл
            sw.Write(buffer,0, buffer.Length);

        } while (true);

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
    
        System.IO.BufferedStream sw = new BufferedStream(System.IO.File.OpenWrite(out_file), buffer.Length);  
        int read = 0;
        do
        {
            read = sr.Read(buffer, 0, buffer.Length);
            if (read == 0) { break; }

            //подрезаем массив на длину в реальности (если буфер менее его размера)
            ReadOnlySpan <byte> iobuffer = buffer.AsSpan(0, read);
            byte[] encrypted_buffer = cipher.Encrypt(iobuffer, RSAEncryptionPadding.OaepSHA1);
            sw.Write(encrypted_buffer, 0, encrypted_buffer.Length);

        //для ускорения    
        if (i % (DIVVER) == 1) { Console.Write("\b \r {0} x {1} -  {2}% ", i, read, (int)((double)i * 100 / SIZE_FILE) ); }
        i++;

    } while (true);

    //закрываем потоки
    sw.Close();

    Console.WriteLine("");
    Console.WriteLine("Файл зашифрован: {0} ", out_file);
    }
//закрываем считку
sr.Close();



