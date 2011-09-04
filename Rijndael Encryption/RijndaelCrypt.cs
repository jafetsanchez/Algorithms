/*
 * Rijndael encryption implementation in C#
 * Copyright (c) 2011 Jafet Sanchez
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#region Using
 
using System;
using System.Security.Cryptography;
using System.Text;
 
#endregion
 
namespace Cubewave.Security.Cryptography
{
    /// <summary>
    /// Rijndael Encryptor / Decryptor Helper
    /// 
    /// <remarks>
    /// Created by: Jafet Sanchez 
    /// Last Update: [date],[author],[description]
    /// 
    public class RijndaelCrypt
    {
        #region Private/Protected Member Variables
         
        /// <summary>
        /// Decryptor
        /// 
        private readonly ICryptoTransform _decryptor;
 
        /// <summary>
        /// Encryptor
        /// 
        private readonly ICryptoTransform _encryptor;
 
        /// <summary>
        /// 16-byte Private Key
        /// 
        private static readonly byte[] IV = Encoding.UTF8.GetBytes("ThisIsUrPassword");
 
        /// <summary>
        /// Public Key
        /// 
        private readonly byte[] _password;
 
        /// <summary>
        /// Rijndael cipher algorithm
        /// 
        private readonly RijndaelManaged _cipher;
 
        #endregion
 
        #region Private/Protected Properties
 
        private ICryptoTransform Decryptor { get { return _decryptor; } }
        private ICryptoTransform Encryptor { get { return _encryptor; } }
 
        #endregion
 
        #region Private/Protected Methods
        #endregion
 
        #region Constructor
 
        /// <summary>
        /// Constructor
        /// 
        /// <param name="password">Public key
        public RijndaelCrypt(string password)
        {
            //Encode digest
            var md5 = new MD5CryptoServiceProvider();
            _password = md5.ComputeHash(Encoding.ASCII.GetBytes(password));
 
            //Initialize objects
            _cipher = new RijndaelManaged();
            _decryptor = _cipher.CreateDecryptor(_password, IV);
            _encryptor = _cipher.CreateEncryptor(_password, IV);
 
        }
 
        #endregion
 
        #region Public Properties
        #endregion
 
        #region Public Methods
 
        /// <summary>
        /// Decryptor
        /// 
        /// <param name="text">Base64 string to be decrypted
        /// <returns>
        public string Decrypt(string text)
        {
            try
            {
                byte[] input = Convert.FromBase64String(text);
 
                var newClearData = Decryptor.TransformFinalBlock(input, 0, input.Length);
                return Encoding.ASCII.GetString(newClearData);
            }
            catch (ArgumentException ae)
            {
                Console.WriteLine("inputCount uses an invalid value or inputBuffer has an invalid offset length. " + ae);
                return null;
            }
            catch (ObjectDisposedException oe)
            {
                Console.WriteLine("The object has already been disposed." + oe);
                return null;
            }
 
 
        }
 
        /// <summary>
        /// Encryptor
        /// 
        /// <param name="text">String to be encrypted
        /// <returns>
        public string Encrypt(string text)
        {
            try
            {
                var buffer = Encoding.ASCII.GetBytes(text);
                return Convert.ToBase64String(Encryptor.TransformFinalBlock(buffer, 0, buffer.Length));
            }
            catch (ArgumentException ae)
            {
                Console.WriteLine("inputCount uses an invalid value or inputBuffer has an invalid offset length. " + ae);
                return null;
            }
            catch (ObjectDisposedException oe)
            {
                Console.WriteLine("The object has already been disposed." + oe);
                return null;
            }
 
        }
 
        #endregion
    }
}