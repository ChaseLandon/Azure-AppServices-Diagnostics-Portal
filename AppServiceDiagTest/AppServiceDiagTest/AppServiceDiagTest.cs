﻿using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;
using System;
using System.Threading;
using System.IO;

namespace AppServiceDiagTest
{
    [TestClass]
    public class AppServiceDiagTest
    {
        private IWebDriver Driver;
        private IConfiguration Config { get; }
        private string ResourceUri = "";
        private string Email = "";
        private string Password = "";

        public AppServiceDiagTest()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.test.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables();

            Config = builder.Build();

            Email = Config["Email"];
            Password = Config["Password"];
            ResourceUri = Config["ResourceUri"];
        }

        [TestMethod]
        public void TestMethod()
        {
            TestDiagPortal();
        }


        [TestInitialize()]
        public void SetupTest()
        {
            var option = new ChromeOptions();
            //option.AddExtension("D:/Azure-AppServices-Diagnostics-Portal/AppServiceDiagTest/AppServiceDiagTest/extension/windows10.crx");
            Driver = new ChromeDriver(option);
            Driver.Manage().Timeouts().ImplicitWait = TimeSpan.FromSeconds(1);
        }

        private void LogIn()
        {
            Driver.FindElement(By.Id("i0116")).SendKeys(Email);
            Driver.FindElement(By.Id("i0116"), 10).SendKeys(Keys.Enter);
            Thread.Sleep(1000 * 10);

            Driver.FindElement(By.XPath("//span[text()='Password']")).Click();
            Thread.Sleep(500);
            Driver.FindElement(By.Id("passwordInput")).SendKeys(Password);
            Driver.FindElement(By.Id("submitButton")).Click();

        }

        private void TestDiagPortal()
        {
            string url = $"https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource{ResourceUri}/troubleshoot";
            Driver.Navigate().GoToUrl(url);
            LogIn();
            //2FA
            Thread.Sleep(1000 * 30);

            var currentIframe = GetIframeElement(0);
            Driver.SwitchTo().Frame(currentIframe);

            //Test Risk Alert
            Driver.FindElement(By.CssSelector(".risk-tile")).Click();
            Assert.IsTrue(Driver.FindElement(By.CssSelector("notification-rendering")).Displayed, "Risk Alert Test");

            //Test avi&perf
            Driver.FindElement(By.XPath("//h3[text()='Availability and Performance']")).Click();
            Thread.Sleep(5000);
            currentIframe = GetIframeElement(1);
            Driver.SwitchTo().Frame(currentIframe);
            //Click Web App down side-nav
            Driver.FindElement(By.XPath("//span[text()='Web App Down']")).Click();
            Assert.IsTrue(Driver.FindElement(By.CssSelector("")).Displayed, "Web App down Test");
            Thread.Sleep(1000 * 20);
            Driver.FindElement(By.XPath("//fab-link/button[text()='View details']")).Click();
        }

        private void TestCaseSubmission()
        {
            string url = $"https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource{ResourceUri}/supportrequest";
            Driver.Navigate().GoToUrl(url);
            LogIn();

            SelectProblemTypeInCaseSubmission("Web app down or reporting errors");

            Thread.Sleep(1000 * 15);
            var currentIFrame = GetIframeElement();
            Driver.SwitchTo().Frame(currentIFrame);
            Thread.Sleep(1000 * 15);
            Assert.IsTrue(Driver.FindElement(By.CssSelector("detector-view")).Displayed, "Case Submission Detector Displayed");
        }

        private IWebElement GetIframeElement(int index = 0)
        {
            Driver.SwitchTo().ParentFrame();
            var iframes = Driver.FindElements(By.CssSelector("iframe.fxs-part-frame"));
            int i = 0;
            IWebElement currentIframe = iframes.GetEnumerator().Current;
            foreach (var iframe in iframes)
            {
                currentIframe = iframe;
                if (i == index) break;
                i++;
            }
            return currentIframe;
        }

        private void SelectProblemTypeInCaseSubmission(string problemSubType)
        {
            Driver.FindElement(By.XPath("//input[@placeholder='Briefly describe your issue']")).SendKeys("test");
            Driver.FindElement(By.XPath("//div[starts-with(text(),'Select a problem type')]")).Click();
            Driver.FindElement(By.XPath("//span[starts-with(text(),'Availability, Performance, and Application Issues')]")).Click();
            Driver.FindElement(By.XPath("//div[starts-with(text(),'Select a problem subtype')]")).Click();
            Driver.FindElement(By.XPath($"//div[starts-with(text(),'{problemSubType}')]")).Click();
            Driver.FindElement(By.XPath("//span[starts-with(text(),'Next: Solutions ')]")).Click();
        }
    }

    public static class WebDriverExtensions
    {
        public static IWebElement FindElement(this IWebDriver driver, By by, int timeoutInSeconds)
        {
            if (timeoutInSeconds > 0)
            {
                var wait = new WebDriverWait(driver, TimeSpan.FromSeconds(timeoutInSeconds));
                return wait.Until(drv => drv.FindElement(by));
            }
            return driver.FindElement(by);
        }
    }
}
