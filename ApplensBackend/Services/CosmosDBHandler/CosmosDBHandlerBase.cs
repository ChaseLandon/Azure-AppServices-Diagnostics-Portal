﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.Configuration;

namespace AppLensV3.Services
{

    public class CosmosDBHandlerBase<T> : ICosmosDBHandlerBase<T> where T : class
    {
        protected string Endpoint;
        protected string Key;
        protected string DatabaseId;
        protected string CollectionId;
        protected string PartitionKey = "/PartitionKey";
        protected CosmosClient Client;
        protected Database Database;
        protected Container Container;

        public CosmosDBHandlerBase(IConfiguration configuration)
        {
            Endpoint = configuration["ApplensTemporaryAccess:Endpoint"];
            Key = configuration["ApplensTemporaryAccess:Key"];
            DatabaseId = configuration["ApplensTemporaryAccess:DatabaseId"];
        }

        protected async Task Inital(IConfiguration configuration)
        {
            //if (configuration["ServerMode"].Equals("internal", StringComparison.OrdinalIgnoreCase)
            //    && (string.IsNullOrWhiteSpace(Endpoint) || string.IsNullOrWhiteSpace(Key)))
            //{
            //    // For internal server mode, if the cosmos db settings are not present, then skip the initialization part.
            //    return;
            //}
            Client = new CosmosClient(Endpoint, Key);
            await CreateDatabaseIfNotExistsAsync();
            await CreateCollectionIfNotExistsAsync();
        }

        public async Task<T> GetItemAsync(string id, string partitionKey)
        {
            //try
            //{
            //    if (string.IsNullOrEmpty(DatabaseId))
            //    {
            //        return null;
            //    }
            //    Document document = await client.ReadDocumentAsync(
            //        UriFactory.CreateDocumentUri(DatabaseId, CollectionId, id),
            //        new RequestOptions { PartitionKey = new PartitionKey(partitionKey) });
            //    return (T)(dynamic)document;
            //}
            //catch (DocumentClientException e)
            //{
            //    if (e.StatusCode == System.Net.HttpStatusCode.NotFound)
            //    {
            //        if (e.Message.Contains("Resource Not Found"))
            //        {
            //            await CreateDatabaseIfNotExistsAsync();
            //            await CreateCollectionIfNotExistsAsync();
            //            return await GetItemAsync(id, partitionKey);
            //        }
            //        return null;
            //    }
            //    else
            //    {
            //        throw;
            //    }
            //}

            try
            {
                var item = await Container.ReadItemAsync<T>(id, new PartitionKey(partitionKey));
                return item;
            }
            catch (CosmosException e)
            {
                if (e.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return null;
                }
                else
                {
                    throw;
                }

            }

        }

        public async Task<List<T>> GetItemsAsync(string partitionKey)
        {
            //IQueryable<T> orderedQuery = client.CreateDocumentQuery<T>(
            //    UriFactory.CreateDocumentCollectionUri(DatabaseId, CollectionId),
            //    new FeedOptions { PartitionKey = new PartitionKey(partitionKey) });

            //if (predicate != null)
            //{
            //    orderedQuery = orderedQuery.Where(predicate);
            //}

            //IDocumentQuery<T> query = orderedQuery.AsDocumentQuery();

            //List<T> results = new List<T>();
            //while (query.HasMoreResults)
            //{
            //    results.AddRange(await query.ExecuteNextAsync<T>());
            //}

            //return results;

            try
            {
                var queryRequestOptions = new QueryRequestOptions()
                {
                    PartitionKey = new PartitionKey(partitionKey)
                };
                return Container.GetItemLinqQueryable<T>(true,null, queryRequestOptions).AsEnumerable().ToList();
            }
            catch (CosmosException e)
            {
                if (e.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return null;
                }
                else
                {
                    throw;
                }
            }

        }

        public async Task<T> CreateItemAsync(T item)
        {
            //return await client.CreateDocumentAsync(UriFactory.CreateDocumentCollectionUri(DatabaseId, CollectionId), item);
            return await Container.CreateItemAsync<T>(item);
        }

        public async Task<T> UpdateItemAsync(T item, string partitionKey)
        {
            if (Container == null)
            {
                return null;
            }
            return await Container.UpsertItemAsync(item, new PartitionKey(partitionKey));
        }

        /// <summary>
        /// Update one property value for the item
        /// </summary>
        /// <returns></returns>
        public async Task<T> PathItemAsync(string id,string partitionKey,string property, Object value)
        {
            var patchOperations = new[]
           {
                PatchOperation.Add($"/{property}",value)
            };

            return await Container.PatchItemAsync<T>(id, new PartitionKey(partitionKey), patchOperations);
        }

        protected async Task CreateDatabaseIfNotExistsAsync()
        {
            try
            {
                Database = Client.GetDatabase(DatabaseId);
            }
            catch (CosmosException e)
            {
                if (e.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    Database = await Client.CreateDatabaseIfNotExistsAsync(DatabaseId);
                }
            }
        }

        protected async Task CreateCollectionIfNotExistsAsync()
        {
            //try
            //{
            //    await client.ReadDocumentCollectionAsync(UriFactory.CreateDocumentCollectionUri(DatabaseId, CollectionId));
            //}
            //catch (DocumentClientException e)
            //{
            //    if (e.StatusCode == System.Net.HttpStatusCode.NotFound)
            //    {
            //        DocumentCollection myCollection = new DocumentCollection();
            //        myCollection.Id = CollectionId;
            //        myCollection.PartitionKey.Paths.Add(PartitionKey);
            //        await client.CreateDocumentCollectionAsync(
            //            UriFactory.CreateDatabaseUri(DatabaseId),
            //            myCollection,
            //            new RequestOptions { OfferThroughput = 400 }
            //            );
            //    }
            //    else
            //    {
            //        throw;
            //    }
            //}

            try
            {
                Container = Database.GetContainer(CollectionId);
            }
            catch (CosmosException e)
            {
                if (e.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    var containerProperties = new ContainerProperties()
                    {
                        Id = CollectionId,
                        PartitionKeyPath = PartitionKey
                    };
                    Container = await Database.CreateContainerIfNotExistsAsync(containerProperties, ThroughputProperties.CreateAutoscaleThroughput(400));
                }
            }
        }
    }
}
