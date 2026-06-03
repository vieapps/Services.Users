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

			var date = now.ToString("yyyyMMdd");
			this.SystemStatistics.Where(kvp => kvp.Key != date).Select(kvp => kvp.Key).ToList().ForEach(key =>
			{
				if (this.SystemStatistics.TryRemove(key, out var minutes))
					Array.Clear(minutes, 0, minutes.Length);
			});

			var systemStatistics = this.GetSystemStatistics(date);
			checkpoint ??= now.AddMinutes(0 - Info.Period - 1);
			var start = checkpoint.Value.Hour * 60 + checkpoint.Value.Minute;
			var end = now.Hour * 60 + now.Minute;
			var min = Math.Min(start, end);
			var max = Math.Max(start, end);
			Array.Clear(systemStatistics, 0, min);
			if (max < systemStatistics.Length - 1)
				Array.Clear(systemStatistics, max + 1, systemStatistics.Length - max - 1);

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
			objects.OrderByDescending(@object => @object.ID).ForEach((@object, index) =>
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
					this.GetDay(dayID, monthID, yearID, current).Load(@object.VisitStatisticsJson, true, _ => counter++);
					if (@object.Day == now.Day && @object.Month == now.Month && @object.Year == now.Year)
						this.SystemStatistics[date] = @object.SystemStatistics;
					if (logOnDays)
						Utility.Logger?.LogInformation($"Load data from JSONs #{index} - {@object.ID} => {yearID}-{monthID}-{dayID} [{@object.VisitStatisticsJson.Count}] -----------");
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
				await Info.SaveAsync(instance, info, this.GetSystemStatistics(info), cancellationToken).ConfigureAwait(false);
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

		public async Task<Statistics> DumpSystemStatisticsAsync(bool all, CancellationToken cancellationToken, string suffix = null)
		{
			var dumpJson = new JObject();
			var statistics = all ? this.SystemStatistics.Select(kvp => kvp) : [this.SystemStatistics.OrderByDescending(kvp => kvp.Key).FirstOrDefault()];
			statistics.ForEach(kvp => dumpJson[kvp.Key] = Info.GetSystemStatisticsJson(kvp.Value));
			await dumpJson.SaveAsTextAsync(this.GetFilePath($"statistics.system{suffix}.json"), cancellationToken).ConfigureAwait(false);

			if (all)
			{
				var date = DateTime.Now.ToString("yyyyMMdd");
				var dayJson = dumpJson.Get<JObject>(date);
				if (dayJson != null)
					for (var hour = 0; hour < 24; hour++)
					{
						var hourID = hour.ToString("00");
						var hourJson = dayJson.Get<JObject>(hourID);
						if (hourJson != null)
							await hourJson.SaveAsTextAsync(this.GetFilePath($"statistics.system{suffix}.{date}-{hourID}.json"), cancellationToken).ConfigureAwait(false);
					}
			}

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

			filePath = this.GetFilePath($"statistics.system{suffix}.json");
			if (File.Exists(filePath))
				try
				{
					var json = await UtilityService.ReadAsJsonAsync(filePath, cancellationToken).ConfigureAwait(false) as JObject;
					var date = json.First()?.GetName() ?? DateTime.Now.ToString("yyyyMMdd");
					this.SystemStatistics[date] = Info.GetSystemStatistics(json.Get<JObject>(date));
				}
				catch (Exception ex)
				{
					Utility.Logger?.LogInformation($"Load dump system JSONs error => {ex.Message}", ex);
				}

			return this;
		}

		internal byte[][] GetSystemStatistics(string date = null, bool returnNullWhenNotExisted = false)
		{
			date ??= DateTime.Now.ToString("yyyyMMdd");
			if (!this.SystemStatistics.TryGetValue(date, out var systemStatistics) || systemStatistics == null)
			{
				if (!returnNullWhenNotExisted)
					this.SystemStatistics[date] = systemStatistics = Info.GetSystemStatistics();
			}
			return systemStatistics;
		}

		internal byte[][] GetSystemStatistics(DateTime? time, bool returnNullWhenNotExisted = false)
			=> this.GetSystemStatistics((time != null ? time.Value : DateTime.Now).ToString("yyyyMMdd"), returnNullWhenNotExisted);

		internal byte[][] GetSystemStatistics((int Year, string Month, Day Day) info)
			=> this.GetSystemStatistics($"{info.Year:0000}{info.Month}{info.Day.Name}");

		internal async Task<byte[][]> GetSystemStatisticsAsync(DateTime time, Func<string, Task> writeLogsAsync, CancellationToken cancellationToken)
		{
			var stepwatch = Stopwatch.StartNew();
			var systemStatistics = this.GetSystemStatistics(time, true);

			var doReload = systemStatistics == null;
			if (doReload)
			{
				systemStatistics = Info.GetSystemStatistics();
				if (writeLogsAsync != null)
					await writeLogsAsync($"Prepare to load statistics [{time:yyyy-MM-dd}]").ConfigureAwait(false);
			}
			else
			{
				if (writeLogsAsync != null)
					await writeLogsAsync($"Get statistics successful [{time:yyyy-MM-dd}] - Execution time: {stepwatch.GetElapsedTimes()}").ConfigureAwait(false);

				var start = time.AddMinutes(-Info.Period);
				var startIndex = start.Hour * 60 + start.Minute;
				var endIndex = time.Hour * 60 + time.Minute;
				doReload = systemStatistics.Skip(startIndex).Take(endIndex - startIndex + 1).Any(statistics => statistics == null);

				if (doReload && writeLogsAsync != null)
					await writeLogsAsync($"Prepare to re-load statistics [{time:yyyy-MM-dd}]").ConfigureAwait(false);
			}

			if (doReload)
			{
				stepwatch.Restart();
				var info = await Statistics.Info.LoadAsync(time, cancellationToken).ConfigureAwait(false);
				if (writeLogsAsync != null)
					await writeLogsAsync($"Load statistics successful [{time:yyyy-MM-dd}] - Execution time: {stepwatch.GetElapsedTimes()}").ConfigureAwait(false);

				stepwatch.Restart();
				var systemStats = info?.SystemStatistics;
				if (systemStats != null)
				{
					if (writeLogsAsync != null)
						await writeLogsAsync($"Prepare statistics successful [{time:yyyy-MM-dd}] - Execution time: {stepwatch.GetElapsedTimes()}").ConfigureAwait(false);

					stepwatch.Restart();
					for (var index = 0; index < systemStats.Length; index++)
						systemStatistics[index] ??= systemStats[index] ?? new JObject().ToBytes();

					if (writeLogsAsync != null)
						await writeLogsAsync($"Assign statistics successful [{time:yyyy-MM-dd}] - Execution time: {stepwatch.GetElapsedTimes()}").ConfigureAwait(false);
				}

				stepwatch.Restart();
				this.SystemStatistics[time.ToString("yyyyMMdd")] = systemStatistics;
				if (writeLogsAsync != null)
					await writeLogsAsync($"Update statistics successful [{time:yyyy-MM-dd}] - Execution time: {stepwatch.GetElapsedTimes()}").ConfigureAwait(false);
			}

			return systemStatistics;
		}

		internal void UpdateSystemStatistics(DateTime time, byte[] statistics)
			=> this.GetSystemStatistics(time)[time.Hour * 60 + time.Minute] = statistics;

		internal void UpdateSystemStatistics(JToken message)
		{
			var jobj = message.Get<JObject>("Time");
			var time = (jobj != null ? jobj.Get<DateTime>("At") : message.Get<DateTime>("Time")).ToLocalTime();
			this.UpdateSystemStatistics(time, message.ToBytes("Statistics", TextFileReader.BufferSize));
		}

		internal ConcurrentDictionary<string, byte[][]> SystemStatistics { get; } = [];

		[BsonIgnoreExtraElements, DebuggerDisplay("Year = {Year}, Month = {Month}, Day = {Day}")]
		[Entity(CollectionName = "Statistics", TableName = "T_Users_Statistics", CacheClass = typeof(Utility), CacheName = "Cache", CreateNewVersionWhenUpdated = false)]
		public class Info : Repository<Info>
		{
			internal static int Period { get; set; } = 10;

			public Info() : base() { }

			public Info((int Year, string Month, Day Day) info) : base()
				=> this.ID = $"{info.Year:0000}{info.Month}{info.Day.Name}{UtilityService.BlankUUID}".Left(32);

			[Sortable(IndexName = "Times")]
			public int Year { get; set; }

			[Sortable(IndexName = "Times")]
			public int Month { get; set; }

			[Sortable(IndexName = "Times")]
			public int Day { get; set; }

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

			internal string _statistics, _systemStatistics;
			internal byte[][] __systemStatistics;
			internal JObject _visitStatisticsJson, _systemStatisticsJson;

			[Property(IsCLOB = true)]
			public string Statistics
			{
				get => this._statistics;
				set => this._statistics = value;
			}

			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore, MessagePackIgnore]
			public JObject VisitStatisticsJson
			{
				get
				{
					if (this._visitStatisticsJson == null)
						this.Prepare();
					return this._visitStatisticsJson;
				}
			}

			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore, MessagePackIgnore]
			public byte[][] SystemStatistics
			{
				get
				{
					if (this.__systemStatistics == null)
					{
						this.Prepare();
						this.__systemStatistics = Info.GetSystemStatistics(this._systemStatistics);
					}
					return this.__systemStatistics;
				}
			}

			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore, MessagePackIgnore]
			public JObject SystemStatisticsJson => this._systemStatisticsJson ??= Info.GetSystemStatisticsJson(this.SystemStatistics);

			void Prepare(JObject visitStatistics = null, string systemStatistics = null)
			{
				if (visitStatistics != null && systemStatistics != null)
				{
					this._statistics = new JObject
					{
						["Visit"] = visitStatistics,
						["System"] = systemStatistics
					}.AsString();
					this._visitStatisticsJson = visitStatistics;
					this._systemStatistics = systemStatistics;
				}
				else
					try
					{
						var json = (string.IsNullOrWhiteSpace(this._statistics) ? "{}" : this._statistics).ToJson();
						this._visitStatisticsJson = json.Get<JObject>("Visit") ?? json as JObject;
						this._systemStatistics = json.Get<string>("System");
					}
					catch (Exception ex)
					{
						Utility.Logger?.LogInformation($"Prepare error [{this.ID}] => {ex.Message}", ex);
					}
				this.__systemStatistics = null;
				this._systemStatisticsJson = null;
			}

			internal static Task<Info> LoadAsync(string date, CancellationToken cancellationToken)
				=> Info.GetAsync($"{date}{UtilityService.BlankUUID}".Left(32), cancellationToken);

			internal static Task<Info> LoadAsync(DateTime date, CancellationToken cancellationToken)
				=> Info.LoadAsync(date.ToString("yyyyMMdd"), cancellationToken);

			internal static Task<Info> LoadAsync((int Year, string Month, Day Day) info, CancellationToken cancellationToken)
				=> Info.LoadAsync($"{info.Year:0000}{info.Month}{info.Day.Name}", cancellationToken);

			internal static async Task<Info> SaveAsync(Info instance, (int Year, string Month, Day Day) info, string systemStatistics, CancellationToken cancellationToken)
			{
				var isCreateNew = instance == null;
				instance ??= new(info);
				instance.Year = info.Year;
				instance.Month = info.Month.As<int>();
				instance.Day = info.Day.Name.As<int>();
				instance.Prepare(info.Day.ToJson(false), systemStatistics);
				if (isCreateNew)
					await Info.CreateAsync(instance, cancellationToken).ConfigureAwait(false);
				else
					await Info.UpdateAsync(instance, true, cancellationToken).ConfigureAwait(false);
				return instance;
			}

			internal static Task<Info> SaveAsync(Info instance, (int Year, string Month, Day Day) info, byte[][] systemStatistics, CancellationToken cancellationToken)
			{
				var statistics = instance?.SystemStatistics;
				if (statistics != null)
					for (var index = 0; index < 1440; index++)
						systemStatistics[index] = systemStatistics[index] ?? statistics[index];
				return Info.SaveAsync(instance, info, Info.GetSystemStatistics(systemStatistics), cancellationToken);
			}

			internal static byte[][] GetSystemStatistics(string statistics)
			{
				var systemStatistics = new byte[1440][];
				if (!string.IsNullOrWhiteSpace(statistics))
					try
					{
						var statisticsBytes = CacheUtils.Helper.DeserializeByMsgPackCLI(statistics.Base64ToBytes().Decompress("zstd")) as byte[][];
						for (var index = 0; index < statisticsBytes.Length; index++)
							systemStatistics[index] = statisticsBytes[index];
					}
					catch (Exception ex)
					{
						Utility.Logger?.LogInformation($"Deserialize error => {ex.Message}", ex);
					}
				return systemStatistics;
			}

			internal static string GetSystemStatistics(byte[][] systemStatistics)
				=> CacheUtils.Helper.SerializeByMsgPackCLI(systemStatistics).Compress("zstd").ToBase64();

			internal static byte[][] GetSystemStatistics(JObject systemStatisticsJson = null)
			{
				var systemStatistics = new byte[1440][];
				if (systemStatisticsJson != null)
					for (var hour = 0; hour < 24; hour++)
					{
						var hourJson = systemStatisticsJson.Get<JObject>(hour.ToString("00"));
						if (hourJson != null)
						{
							var start = hour * 60;
							for (var minute = 0; minute < 60; minute++)
								systemStatistics[start + minute] = hourJson.Get<JObject>(minute.ToString("00"))?.ToBytes("Statistics", TextFileReader.BufferSize);
						}
					}
				return systemStatistics;
			}

			internal static JObject GetSystemStatisticsJson(byte[][] systemStatistics)
			{
				var json = new JObject();
				for (var hour = 0; hour < 24; hour++)
				{
					var start = hour * 60;
					var minutes = new JObject();
					for (var minute = 0; minute < 60; minute++)
					{
						var minuteJson = systemStatistics[start + minute]?.GetString();
						if (minuteJson != null)
							minutes[minute.ToString("00")] = minuteJson.ToJson();
					}
					if (minutes.Count > 0)
						json[hour.ToString("00")] = minutes;
				}
				for (var hour = 0; hour < 24; hour++)
				{
					var hourID = hour.ToString("00");
					var hourJson = json.Get<JObject>(hourID);
					if (hourJson == null || hourJson.Count < 1)
						json.Remove(hourID);
				}
				return json;
			}
		}
	}
}