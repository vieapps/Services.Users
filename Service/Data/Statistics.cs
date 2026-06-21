#region Related components
using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using MongoDB.Bson.Serialization.Attributes;
using MsgPack.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Repository;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Users
{
	public class Statistics
	{
		public Statistics() { }

		internal Year Current { get; } = new(null);

		internal ConcurrentDictionary<string, Year> Years { get; } = [];

		#region Year
		public class Year : StatisticInfo
		{
			internal Year(string yearID	, int counters = 0)
			{
				this.Name = yearID ?? DateTime.Now.Year.ToString("0000");
				this.Counters = counters;
			}

			internal ConcurrentDictionary<string, Month> Months { get; } = [];

			public long Sum(bool sumOnChildren = false)
			{
				long sum = 0;
				foreach (var month in this.Months.Values)
					sum += sumOnChildren ? month.Sum(true) : month.Counters;
				return this.Counters = sum;
			}

			internal JObject ToJson(bool asSummary, bool addDayDetails = true, bool addHourDetails = true)
			{
				var json = new JObject();
				this.Months.Values.OrderByDescending(month => month.Name).ForEach(month => json[month.Name] = month.ToJson(asSummary, addDayDetails, addHourDetails));

				if (asSummary)
					json = new JObject
					{
						["Counters"] = this.Sum(),
						["AverageOfOneMonth"] = this.Months.IsEmpty ? 0 : this.Counters / this.Months.Count,
						["Months"] = json
					};

				return json;
			}
		}
		#endregion

		#region Month
		public class Month : StatisticInfo
		{
			internal int Year { get; } = DateTime.Now.Year;

			internal Month(int year, string monthID, int counters = 0)
			{
				this.Year = year;
				this.Name = monthID ?? DateTime.Now.Month.ToString("00");
				this.Counters = counters;
			}

			internal ConcurrentDictionary<string, Day> Days { get; } = [];

			public long Sum(bool sumOnChildren = false)
			{
				long sum = 0;
				foreach (var day in this.Days.Values)
					sum += sumOnChildren ? day.Sum() : day.Counters;
				return this.Counters = sum;
			}

			internal JObject ToJson(bool asSummary, bool addDayDetails = true, bool addHourDetails = true)
			{
				var days = new JObject();
				this.Days.Values.OrderByDescending(day => day.Name).ForEach(day => days[day.Name] = day.ToJson(asSummary, addHourDetails));

				if (!asSummary)
				{
					if (!addDayDetails)
						days["Counters"] = this.Sum();
					return days;
				}

				var json = new JObject
				{
					["Counters"] = this.Sum(),
					["AverageOfOneDay"] = this.Days.IsEmpty ? 0 : this.Counters / this.Days.Count					
				};

				if (addDayDetails)
					json["Days"] = days;

				return json;
			}
		}
		#endregion

		#region Day
		public class Day : StatisticInfo
		{
			internal readonly int[] Minutes = new int[1440];

			internal Day(string dayID, int counters = 0)
			{
				this.Name = dayID ?? DateTime.Now.Day.ToString("00");
				this.Counters = counters;
			}

			internal Day Load(JObject hoursJson, bool asUpdate, Action<Day> onCompleted = null)
			{
				if (hoursJson != null)
				{
					foreach (var kvpHour in hoursJson)
					{
						var hour = kvpHour.Key.As<int>();
						if (kvpHour.Value is JObject hourJson)
							foreach (var kvpMinute in hourJson)
							{
								var minute = kvpMinute.Key.As<int>();
								var counters = (kvpMinute.Value as JValue ?? new JValue(0)).Value.As<int>();
								if (asUpdate)
									this.Update(hour, minute, counters);
								else
									this.Set(hour, minute, counters);
							}
					}
					this.Sum();
				}
				onCompleted?.Invoke(this);
				return this;
			}

			public long Sum()
			{
				var sum = 0;
				for (var index = 0; index < 1440; index++)
					sum += this.Minutes[index];
				return this.Counters = sum;
			}

			internal int Update(int hour, int minute, int counter)
			{
				var delta = 1;
				var index = hour * 60 + minute;

				if (counter < 1)
					Interlocked.Increment(ref this.Minutes[index]);

				else
				{
					int current;
					do
					{
						current = this.Minutes[index];
						if (current >= counter)
							return 0;
					} while (Interlocked.CompareExchange(ref this.Minutes[index], counter, current) != current);
					delta = counter - current;
				}

				this.Counters += delta;
				return delta;
			}

			internal int Set(int hour, int minute, int counter)
			{
				var index = hour * 60 + minute;
				var current = this.Minutes[index];
				this.Minutes[index] = counter;
				this.Counters += Math.Max(0, counter - current);
				return counter;
			}

			internal JObject ToJson(bool asSummary, bool addHourDetails = true)
			{
				var json = new JObject();

				for (var hour = 23; hour >= 0; hour--)
				{
					var minutes = new JObject();
					var hourSum = 0;
					var start = hour * 60;
					for (var minute = 59; minute >= 0; minute--)
					{
						var counter = this.Minutes[start + minute];
						hourSum += counter;
						if (counter > 0)
							minutes[$"{minute:00}"] = counter;
					}

					if (minutes.Count > 0)
						json[$"{hour:00}"] = addHourDetails
							? minutes
							: new JObject
								{
									["Counters"] = hourSum,
									["AverageOfOneMinute"] = hourSum / this.Minutes.Skip(start).Take(60).Count(counter => counter > 0)
								};
				}

				if (!asSummary && !addHourDetails)
					json["Counters"] = this.Sum();

				return asSummary
					? json.Count > 0
						? new JObject
							{
								["Counters"] = this.Sum(),
								["AverageOfOneHour"] = this.Counters / 24,
								["Hours"] = json
							}
						: new JObject
							{
								["Counters"] = 0
							}
					: json;
			}
		}
		#endregion

		#region Get Year/Month/Day
		public Year GetYear(string yearID, bool currentFirst)
		{
			var now = DateTime.Now.Year.ToString("0000");
			yearID ??= now;
			return currentFirst && yearID == now
				? this.Current
				: this.Years.TryGetValue(yearID, out var year)
					? year
					: this.Years.TryAdd(yearID, year = new Year(yearID)) ? year : this.Years[yearID];
		}

		public Month GetMonth(string monthID, string yearID, bool currentFirst)
		{
			monthID ??= DateTime.Now.Month.ToString("00");
			var year = this.GetYear(yearID, currentFirst);
			return year.Months.TryGetValue(monthID, out var month)
				? month
				: year.Months.TryAdd(monthID, month = new Month(year.Name.As<int>(), monthID)) ? month : year.Months[monthID];
		}

		public Day GetDay(string dayID = null, string monthID = null, string yearID = null, bool currentFirst = true)
		{
			dayID ??= DateTime.Now.Day.ToString("00");
			var month = this.GetMonth(monthID, yearID, currentFirst);
			return month.Days.TryGetValue(dayID, out var day)
				? day
				: month.Days.TryAdd(dayID, day = new Day(dayID)) ? day : month.Days[dayID];
		}
		#endregion

		public long Total => this.Years.Values.Sum(year => year.Sum());

		public long TotalOfCurrentYear => this.GetYear(null, false).Sum();

		public long TotalOfCurrentMonth => this.GetMonth(null, null, false).Sum();

		public long TotalOfCurrentDay => this.GetDay().Counters;

		public int Get(string minuteID = null, string hourID = null, string dayID = null, string monthID = null, string yearID = null)
		{
			var now = DateTime.Now;
			yearID ??= now.Year.ToString("0000");
			monthID ??= now.Month.ToString("00");
			dayID ??= now.Day.ToString("00");
			hourID ??= now.Hour.ToString("00");
			minuteID ??= now.Minute.ToString("00");

			var hour = hourID.As<int>();
			var minute = minuteID.As<int>();
			var day = this.GetDay(dayID, monthID, yearID, now.ToString("yyyyMMdd").Equals($"{yearID}{monthID}{dayID}"));
			var index = hour * 60 + minute;
			return index < 0 || index >= 1440 ? 0 : day.Minutes[index];
		}

		public int Update(int counter = 0, string minuteID = null, string hourID = null, string dayID = null, string monthID = null, string yearID = null)
		{
			var now = DateTime.Now;
			yearID ??= now.Year.ToString("0000");
			monthID ??= now.Month.ToString("00");
			dayID ??= now.Day.ToString("00");
			hourID ??= now.Hour.ToString("00");
			minuteID ??= now.Minute.ToString("00");

			var hour = hourID.As<int>();
			var minute = minuteID.As<int>();
			var day = this.GetDay(dayID, monthID, yearID, now.ToString("yyyyMMdd").Equals($"{yearID}{monthID}{dayID}"));
			return day.Update(hour, minute, counter);
		}

		public int Update(JObject data)
		{
			var counter = data.Get("Counters", 0);
			var minuteID = data.Get<string>("Minute");
			var hourID = data.Get<string>("Hour");
			var dayID = data.Get<string>("Day");
			var monthID = data.Get<string>("Month");
			var yearID = data.Get<string>("Year");
			return this.Update(counter, minuteID, hourID, dayID, monthID, yearID);
		}

		public JObject ToJson(bool asSummary = false, bool addDayDetails = true, bool addHourDetails = true, Func<IEnumerable<Year>, JObject, JObject> transformer = null)
		{
			var json = new JObject();
			var years = this.Years.Values.OrderByDescending(year => year.Name).ToList();
			years.ForEach(year => json[year.Name] = year.ToJson(asSummary, addDayDetails, addHourDetails));
			return transformer != null ? transformer(years, json) : json;
		}

		public Statistics Normalize(DateTime? checkpoint = null)
		{
			var now = DateTime.Now;
			var currentYearID = now.Year.ToString("0000");
			var currentMonthID = now.Month.ToString("00");
			var currentDayID = now.Day.ToString("00");

			this.Current.Months.Values.ForEach(month =>
			{
				if (month.Days.Count > 1)
					month.Days.Where(kvp => kvp.Key != currentDayID).Select(kvp => kvp.Key).ToList().ForEach(dayID =>
					{
						if (month.Days.TryRemove(dayID, out var day))
						{
							day.Sum();
							this.GetMonth(month.Name, this.Current.Name, false).Days[day.Name] = day;
						}
					});
			});

			if (this.Current.Months.Count > 1)
				this.Current.Months.Where(kvp => kvp.Key != currentMonthID).Select(kvp => kvp.Key).ToList().ForEach(monthID => this.Current.Months.Remove(monthID));

			var currentDay = this.GetDay(currentDayID, currentMonthID, currentYearID, true);
			this.GetMonth(currentMonthID, currentYearID, false).Days[currentDay.Name] = currentDay;

			return this;
		}

		public async Task<Statistics> LoadAsync(bool current, CancellationToken cancellationToken, bool doNormalize = true, bool logOnDays = false)
		{
			var now = DateTime.Now;
			var currentYearID = now.Year.ToString("0000");
			var currentMonthID = now.Month.ToString("00");
			var currentDayID = now.Day.ToString("00");

			var filter = current
				? Filters<Info>.And
					(
						Filters<Info>.Equals("Year", now.Year),
						Filters<Info>.Equals("Month", now.Month),
						Filters<Info>.Equals("Day", now.Day)
					)
				: null;
			var sort = Sorts<Info>.Descending("Year").ThenByDescending("Month").ThenByDescending("Day");

			var objects = current ? await Info.FindAsync(filter, sort, 1, 1, null, cancellationToken).ConfigureAwait(false) ?? [] : [];
			if (!current)
			{
				var pageSize = 20;
				var pageNumber = 0;
				var totalRecords = await Info.CountAsync(filter, null, cancellationToken).ConfigureAwait(false);
				var totalPages = (totalRecords, pageSize).GetTotalPages();
				while (pageNumber < totalPages)
				{
					pageNumber++;
					objects.AddRange(await Info.FindAsync(filter, sort, pageSize, pageNumber, null, cancellationToken).ConfigureAwait(false) ?? []);
				}
				await Enumerable.Range(0, 31).Select(day => now.AddDays(-day)).ForEachAsync(async day =>
				{
					var instanceID = $"{day:yyyyMMdd}{UtilityService.BlankUUID}".Left(32);
					var instance = objects.FirstOrDefault(@object => @object.ID == instanceID) ?? await Statistics.Info.LoadAsync(day, cancellationToken).ConfigureAwait(false);
					if (instance != null && objects.FirstOrDefault(@object => @object.ID == instance.ID) == null)
						objects.Add(instance);
				}, true, false).ConfigureAwait(false);
				Utility.Logger?.LogInformation($"{objects.Count:###,###,##0} statistics were loaded from database -----------");
			}

			int counter = 0, refined = 0;
			objects.OrderByDescending(@object => @object.ID).ForEach(async (@object, index) =>
			{
				var date = @object.ID.Left(8);
				var yearID = @object.Year > 0 ? @object.Year.ToString("0000") : date.Left(4);
				var monthID = @object.Month > 0 ? @object.Month.ToString("00") : date.Substring(4, 2);
				var dayID = @object.Day > 0 ? @object.Day.ToString("00") : date.Right(2);

				if (@object.Year < 1 || @object.Month < 1 || @object.Day < 1)
				{
					refined++;
					@object.Day = dayID.As<int>();
					@object.Month = monthID.As<int>();
					@object.Year = yearID.As<int>();
					Info.UpdateAsync(@object, true, cancellationToken).Execute(ex => Utility.Logger?.LogInformation($"Error occurred while refining an object [{@object.ID}] => {ex.Message}", ex));
					if (logOnDays)
						Utility.Logger?.LogInformation($"Refine data #{index} - {@object.ID} => {yearID}-{monthID}-{dayID} -----------");
				}

				if (date == "00000000")
				{
					refined++;
					Info.DeleteAsync(@object.ID, null, cancellationToken).Execute(ex => Utility.Logger?.LogInformation($"Error occurred while deleting an object [{@object.ID}] => {ex.Message}", ex));
					if (logOnDays)
						Utility.Logger?.LogInformation($"Delete wrong date => #{index} - {@object.ID} -----------");
				}

				else
				{
					this.GetDay(dayID, monthID, yearID, current).Load(@object.Counters, true, _ => counter++);
					if (logOnDays)
						Utility.Logger?.LogInformation($"Load data from JSONs #{index} - {@object.ID} => {yearID}-{monthID}-{dayID} -----------");
				}
			});

			if (!current)
				Utility.Logger?.LogInformation($"{counter:###,###,##0} statistics were constructed {(refined > 0 ? $"({refined:###,###,##0} statistic(s) were refined)" : "")} -----------");

			if (doNormalize)
				return this.Normalize();

			var currentDay = this.GetDay(currentDayID, currentMonthID, currentYearID, true);
			this.GetMonth(currentMonthID, currentYearID, false).Days[currentDay.Name] = currentDay;
			return this;
		}

		internal async Task<Statistics> SaveAsync(CancellationToken cancellationToken)
		{
			await this.Current.Months.Values.Select(month => month.Days.Values.Select(day => (month.Year, Month: month.Name, Day: day))).SelectMany(info => info).ToList().ForEachAsync(async info =>
			{
				var instance = await Info.LoadAsync(info, cancellationToken).ConfigureAwait(false);
				await Info.SaveAsync(instance, info, cancellationToken).ConfigureAwait(false);
			}, true, false).ConfigureAwait(false);
			return this.Normalize();
		}

		string GetFilePath(string filename)
			=> Path.Combine(UtilityService.GetAppSetting("Path:Status", "status"), filename);

		public async Task<Statistics> DumpVisitStatisticsAsync(bool all, CancellationToken cancellationToken, string suffix = null)
		{
			var filePath = this.GetFilePath($"statistics.visit{suffix}.json");
			if (all)
				await this.ToJson().SaveAsTextAsync(filePath, cancellationToken).ConfigureAwait(false);
			else
				await new JObject
				{
					[this.Current.Name] = this.Current.ToJson(false)
				}.SaveAsTextAsync(filePath, cancellationToken).ConfigureAwait(false);
			return this;
		}

		public async Task<Statistics> LoadDumpStatisticsAsync(CancellationToken cancellationToken, string suffix = null)
		{
			var filePath = this.GetFilePath($"statistics.visit{suffix}.json");
			if (File.Exists(filePath))
				try
				{
					var json = await UtilityService.ReadAsJsonAsync(filePath, cancellationToken).ConfigureAwait(false) as JObject;
					json.ForEach(year => (year.Value as JObject).ForEach(month => (month.Value as JObject).ForEach(day => this.GetDay(day.Key, month.Key, year.Key).Load(day.Value as JObject, false))));
				}
				catch (Exception ex)
				{
					Utility.Logger?.LogInformation($"Load dump visit JSONs error => {ex.Message}", ex);
				}
			return this;
		}

		[BsonIgnoreExtraElements, DebuggerDisplay("Year = {Year}, Month = {Month}, Day = {Day}")]
		[Entity(CollectionName = "Statistics", TableName = "T_Users_Statistics", CacheClass = typeof(Utility), CacheName = "Cache", CreateNewVersionWhenUpdated = false)]
		public class Info : Repository<Info>
		{
			internal static int Period { get; set; } = 10;

			public Info() : base() { }

			public Info((int Year, string Month, Day Day) info) : base()
				=> this.ID = $"{info.Year:0000}{info.Month}{info.Day.Name}{UtilityService.BlankUUID}".Left(32);

			[Sortable(IndexName = "Times", Reverse = true)]
			public int Year { get; set; }

			[Sortable(IndexName = "Times", Reverse = true)]
			public int Month { get; set; }

			[Sortable(IndexName = "Times", Reverse = true)]
			public int Day { get; set; }

			string _statistics;

			[Property(IsCLOB = true)]
			public string Statistics
			{
				get => this._statistics;
				set
				{
					this._statistics = value;
					var json = JObject.Parse(string.IsNullOrWhiteSpace(this._statistics) ? "{}" : this._statistics);
					this._counters = json.Get<JObject>("Visit") ?? json;
				}
			}

			JObject _counters;

			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore, MessagePackIgnore]
			public JObject Counters
			{
				get => this._counters;
				set
				{
					this._counters = value;
					this._statistics = this._counters.AsString();
				}
			}

			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore, MessagePackIgnore]
			public override string Title { get; set; }

			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore, MessagePackIgnore]
			public override string SystemID { get; set; }

			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore, MessagePackIgnore]
			public override string RepositoryID { get; set; }

			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore, MessagePackIgnore]
			public override string RepositoryEntityID { get; set; }

			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore, MessagePackIgnore]
			public override Privileges OriginalPrivileges { get; set; }

			internal static Task<Info> LoadAsync(string date, CancellationToken cancellationToken)
				=> Info.GetAsync($"{date}{UtilityService.BlankUUID}".Left(32), cancellationToken);

			internal static Task<Info> LoadAsync(DateTime date, CancellationToken cancellationToken)
				=> Info.LoadAsync(date.ToString("yyyyMMdd"), cancellationToken);

			internal static Task<Info> LoadAsync((int Year, string Month, Day Day) info, CancellationToken cancellationToken)
				=> Info.LoadAsync($"{info.Year:0000}{info.Month}{info.Day.Name}", cancellationToken);

			internal static async Task<Info> SaveAsync(Info instance, (int Year, string Month, Day Day) info, CancellationToken cancellationToken)
			{
				var isCreateNew = instance == null;
				instance ??= new(info);
				instance.Year = info.Year;
				instance.Month = info.Month.As<int>();
				instance.Day = info.Day.Name.As<int>();
				instance.Counters = info.Day.ToJson(false);
				if (isCreateNew)
					await Info.CreateAsync(instance, cancellationToken).ConfigureAwait(false);
				else
					await Info.UpdateAsync(instance, true, cancellationToken).ConfigureAwait(false);
				return instance;
			}
		}
	}
}