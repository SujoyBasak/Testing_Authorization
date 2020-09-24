using AuthorizationService;
using AuthorizationService.Controllers;
using AuthorizationService.Provider;
using AuthorizationService.Repository;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace Authorization.Testing
{
    public class TokenControllerTest
    {
        public Dictionary<string, string> dc = new Dictionary<string, string>()
        {
               {"Sujoy","Basak"},
               {"Supriya","Sinha"},
               {"Aman","Bharti"},
               {"Shubham","Debnath"}
        };

        [TestCase("Sujoy","Basak")]
        [TestCase("Aman","Bharti")]
        public void TokenGenarationTest(string name, string pass)
        {
            
            Mock<IConfiguration> config = new Mock<IConfiguration>();
            config.Setup(p=>p["Jwt:Key"]).Returns("ThisismySecretKey");
            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);
            AuthProvider cp = new AuthProvider(mock.Object);
            Authenticate user = new Authenticate()
            {
                Name = name,
                Password = pass
            };
            string result = cp.GenerateJSONWebToken(user,config.Object);
            Assert.IsNotNull(result);
        }

        [Test]
        public void FailedTokenGenarationTest()
        {
            Mock<IConfiguration> config = new Mock<IConfiguration>();
            config.Setup(p => p["Jwt:Key"]).Returns("ThisismySecretKey");
            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);
            AuthProvider cp = new AuthProvider(mock.Object);            
            string result = cp.GenerateJSONWebToken(null, config.Object);
            Assert.IsNull(result);
        }

        [TestCase("Sujoy", "Basak")]
        public void CorrectCredProviderTest(string name, string pass)
        {

            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);

            AuthProvider cp = new AuthProvider(mock.Object);
            Authenticate user = new Authenticate()
            {
                Name = name,
                Password = pass
            };
            Authenticate result = cp.AuthenticateUser(user);
            Assert.IsNotNull(result);
        }

        [TestCase("Sujoy", "Basak123")]
        public void WrongCredProviderTest(string name, string pass)
        {

            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);

            AuthProvider cp = new AuthProvider(mock.Object);
            Authenticate user = new Authenticate()
            {
                Name = name,
                Password = pass
            };
            Authenticate result = cp.AuthenticateUser(user);
            Assert.IsNull(result);
        }

        [Test]
        public void CorrectCredControllerTest()
        {
            Authenticate cred = new Authenticate()
            {
                Name = "Sujoy",
                Password = "Basak"
            };
            
            Mock<IConfiguration> config = new Mock<IConfiguration>();            
            Mock<IAuthProvider> mock = new Mock<IAuthProvider>();
            mock.Setup(p => p.AuthenticateUser(cred)).Returns(cred);
            mock.Setup(q => q.GenerateJSONWebToken(cred, config.Object)).Returns("Token");

            TokenController cp = new TokenController(config.Object,mock.Object);
           
            OkObjectResult result = cp.Login(cred) as OkObjectResult;
            Assert.AreEqual(200,result.StatusCode);
        }

        [Test]
        public void WrongCredControllerTest()
        {
            try
            {
                Authenticate cred = new Authenticate()
                {
                    Name = "Sujoy",
                    Password = "Basak"
                };
                Mock<IConfiguration> config = new Mock<IConfiguration>();                
                Mock<IAuthProvider> mock = new Mock<IAuthProvider>();                
                mock.Setup(q => q.GenerateJSONWebToken(cred, config.Object)).Returns("Token");                
                TokenController cp = new TokenController(config.Object, mock.Object);
                Authenticate user = new Authenticate()
                {
                    Name = "Sujoy",
                    Password = "Basak123"
                };
                OkObjectResult result = cp.Login(user) as OkObjectResult;
                Assert.AreNotEqual(200, result.StatusCode);
            }
            catch(Exception e)
            {
                Assert.AreEqual("Object reference not set to an instance of an object.",e.Message);
            }
            
        }

    }
}