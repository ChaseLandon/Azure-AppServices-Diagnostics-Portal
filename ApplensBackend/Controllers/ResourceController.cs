﻿using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace AppLensV3
{
    [Authorize(Policy = "ApplensAccess")]
    public class ResourceController : Controller
    {
        IObserverClientService _observerService;

        public ResourceController(IObserverClientService observerService)
        {
            _observerService = observerService;
        }

        [HttpGet("api/sites/{siteName}")]
        [HttpOptions("api/sites/{siteName}")]
        public async Task<IActionResult> GetSite(string siteName)
        {
            return await GetSiteInternal(null, siteName);
        }

        [HttpGet("api/containerapps/{containerAppName}")]
        [HttpOptions("api/containerapps/{containerAppName}")]
        public async Task<IActionResult> GetContainerApp(string containerAppName)
        {
            return await GetContainerAppInternal(containerAppName);
        }

        [HttpGet("api/staticwebapps/{defaultHostNameOrAppName}")]
        [HttpOptions("api/staticwebapps/{defaultHostNameOrAppName}")]
        public async Task<IActionResult> GetStaticWebApp(string defaultHostNameOrAppName)
        {
            return await GetStaticWebAppInternal(defaultHostNameOrAppName);
        }

        [HttpGet]
        [Route("api/stamps/{stamp}/sites/{siteName}")]
        public async Task<IActionResult> GetSite(string stamp, string siteName)
        {
            return await GetSiteInternal(stamp, siteName);
        }

        [HttpGet]
        [Route("api/stamps/{stamp}/sites/{siteName}/details")]
        public async Task<IActionResult> GetSiteDetails(string stamp, string siteName)
        {
            return await GetSiteInternal(stamp, siteName, details: true);
        }

        [HttpGet]
        [Route("api/stamps/{stamp}/sites/{siteName}/postBody")]
        public async Task<IActionResult> GetSiteRequestBody(string stamp, string siteName)
        {
            var sitePostBody = await _observerService.GetSitePostBody(stamp, siteName);

            return Ok(new { Details = sitePostBody.Content });
        }

        [HttpGet]
        [Route("api/hostingEnvironments/{hostingEnvironmentName}/postBody")]
        public async Task<IActionResult> GetHostingEnvironmentRequestBody(string hostingEnvironmentName)
        {
            var hostingEnvironmentPostBody = await _observerService.GetHostingEnvironmentPostBody(hostingEnvironmentName);

            return Ok(new { Details = hostingEnvironmentPostBody.Content });
        }

        [HttpGet("api/hostingEnvironments/{hostingEnvironmentName}")]
        [HttpOptions("api/hostingEnvironments/{hostingEnvironmentName}")]
        public async Task<IActionResult> GetHostingEnvironmentDetails(string hostingEnvironmentName)
        {
            var hostingEnvironmentDetails = await _observerService.GetHostingEnvironmentDetails(hostingEnvironmentName);

            var details = new { Details = hostingEnvironmentDetails.Content };

            if (hostingEnvironmentDetails.StatusCode == HttpStatusCode.NotFound)
            {
                return NotFound(details);
            }

            return Ok(details);
        }

        private async Task<IActionResult> GetSiteInternal(string stamp, string siteName, bool details = false)
        {
            var siteDetailsTask = stamp == null ? _observerService.GetSite(siteName) : _observerService.GetSite(stamp, siteName, details);
            var siteDetailsResponse = await siteDetailsTask;

            var response = new
            {
                SiteName = siteName,
                Details = siteDetailsResponse.Content
            };

            if (siteDetailsResponse.StatusCode == HttpStatusCode.NotFound)
            {
                return NotFound(response);
            }

            return Ok(response);
        }

        private async Task<IActionResult> GetContainerAppInternal(string containerAppName)
        {
            var containerAppsTask = _observerService.GetContainerApp(containerAppName);
            var containerAppsResponse = await containerAppsTask;

            var response = new
            {
                ContainerAppName = containerAppName,
                Details = containerAppsResponse.Content
            };

            if (containerAppsResponse.StatusCode == HttpStatusCode.NotFound)
            {
                return NotFound(response);
            }

            return Ok(response);
        }

        private async Task<IActionResult> GetStaticWebAppInternal(string defaultHostNameOrAppName)
        {
            var staticWebAppsTask = _observerService.GetStaticWebApp(defaultHostNameOrAppName);
            var staticWebAppsResponse = await staticWebAppsTask;

            var response = new
            {
                DefaultHostNameOrAppName = defaultHostNameOrAppName,
                Details = staticWebAppsResponse.Content
            };

            if (staticWebAppsResponse.StatusCode == HttpStatusCode.NotFound)
            {
                return NotFound(response);
            }

            return Ok(response);
        }

        [HttpGet]
        [Route("api/stamps/{stampName}")]
        public async Task<IActionResult> GetStampBody(string stampName)
        {
            return await GetStampBodyInternal(stampName);
        }

        private async Task<IActionResult> GetStampBodyInternal(string stampName)
        {
            var stampDetailsTask = _observerService.GetStampBody(stampName);
            var stampDetailsResponse = await stampDetailsTask;

            var response = new
            {
                Name = stampName,
                Details = stampDetailsResponse.Content
            };

            if (stampDetailsResponse.StatusCode == HttpStatusCode.NotFound)
            {
                return NotFound(response);
            }

            return Ok(response);
        }
    }
}
