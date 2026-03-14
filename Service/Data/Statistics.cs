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
		public Statistics(JObject json = null)
			=> this.Load(json);

		internal Year Current { get; } = new();

		internal ConcurrentDictionary<string, Year> Years { get; } = [];

		#region Year
		public class Year : StatisticInfo
		{
			public Year() : this($"{DateTime.Now:yyyy}") { }

			internal Year(string yearID, int counters = 0)
			{
				this.Name = yearID;
				this.Counters = counters;
			}

			internal ConcurrentDictionary<string, Month> Months { get; } = [];

			internal int Increase(int counter)
				=> this.Counters += counter;

			public int Sum(bool sumOnChildren = false)
			{
				var sum = 0;
				foreach (var month in this.Months.Values)
					sum += sumOnChildren ? month.Sum(true) : month.Counters;
				return this.Counters = sum;
			}

			internal JObject ToJson(bool asSummary, bool addDayDetails, bool addHourDetails)
			{
				var json = new JObject();
				this.Months.Values.OrderBy(month => month.Name).ForEach(month => json[month.Name] = month.ToJson(asSummary, addDayDetails, addHourDetails));
				if (asSummary)
					json = new JObject
					{
						["Counters"] = this.Counters == 0 ? this.Sum() : this.Counters,
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

			public Month() : this(DateTime.Now.Year, $"{DateTime.Now:MM}") { }

			internal Month(int year, string monthID, int counters = 0)
			{
				this.Year = year;
				this.Name = monthID;
				this.Counters = counters;
			}

			internal ConcurrentDictionary<string, Day> Days { get; } = [];

			internal int Increase(int counter)
				=> this.Counters += counter;

			public int Sum(bool sumOnChildren = false)
			{
				var sum = 0;
				foreach (var day in this.Days.Values)
					sum += sumOnChildren ? day.Sum() : day.Counters;
				return this.Counters = sum;
			}

			internal JObject ToJson(bool asSummary, bool addDayDetails, bool addHourDetails)
			{
				var days = new JObject();
				this.Days.Values.OrderBy(day => day.Name).ForEach(day => days[day.Name] = day.ToJson(asSummary, addHourDetails));
				if (!asSummary)
					return days;
				var json = new JObject
				{
					["Counters"] = this.Counters == 0 ? this.Sum() : this.Counters,
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

			public Day() : this($"{DateTime.Now:dd}") { }

			internal Day(string dayID, int counters = 0)
			{
				this.Name = dayID;
				this.Counters = counters;
			}

			public int Sum()
			{
				var sum = 0;
				for (var index = 0; index < 1440; index++)
					sum += this.Minutes[index];
				return this.Counters = sum;
			}

			internal int Increase(int hour, int minute)
			{
				var index = hour * 60 + minute;
				var counter = Interlocked.Increment(ref this.Minutes[index]);
				this.Counters++;
				return counter;
			}

			internal int Set(int hour, int minute, int counter)
			{
				var index = hour * 60 + minute;
				var current = this.Minutes[index];
				this.Minutes[index] = counter;
				this.Counters += counter - current;
				return counter;
			}

			internal int Merge(int hour, int minute, int counter)
			{
				var index = hour * 60 + minute;
				int current;
				do
				{
					current = this.Minutes[index];
					if (current >= counter)
						return 0;
				} while (Interlocked.CompareExchange(ref this.Minutes[index], counter, current) != current);
				var delta = counter - current;
				this.Counters += delta;
				return delta;
			}

			internal JObject ToJson(bool asSummary, bool addHourDetails = true)
			{
				var json = new JObject();
				for (var hour = 0; hour < 24; hour++)
				{
					var start = hour * 60;
					var hourSum = 0;
					var minutes = new JObject();
					for (var minute = 0; minute < 60; minute++)
					{
						var value = this.Minutes[start + minute];
						hourSum += value;
						minutes[$"{minute:00}"] = value;
					}
					if (asSummary)
						json[$"{hour:00}"] = new JObject
						{
							["Counters"] = hourSum,
							["AverageOfOneMinute"] = hourSum / 60
						};
					else
						json[$"{hour:00}"] = minutes;
				}
				if (asSummary)
					json = new JObject
					{
						["Counters"] = this.Counters == 0 ? this.Sum() : this.Counters,
						["AverageOfOneHour"] = this.Counters / 24,
						["Hours"] = json
					};
				return json;
			}
		}
		#endregion

		#region Total
		public long Total
		{
			get
			{
				long total = 0;
				foreach (var year in this.Years.Values)
					total += year.Counters == 0 ? year.Sum(true) : year.Counters;
				return total;
			}
		}

		public long TotalOfCurrentYear
		{
			get
			{
				var year = this.GetYear(null, false);
				return year.Counters == 0 ? year.Sum(true) : year.Counters;
			}
		}

		public long TotalOfCurrentMonth
		{
			get
			{
				var month = this.GetMonth(null, null, false);
				return month.Counters == 0 ? month.Sum(true) : month.Counters;
			}
		}

		public long TotalOfCurrentDay
		{
			get
			{
				var day = this.GetDay();
				return day.Counters == 0 ? day.Sum() : day.Counters;
			}
		}
		#endregion

		public Year GetYear(string yearID, bool currentFirst = true)
		{
			var now = $"{DateTime.Now:yyyy}";
			yearID ??= now;
			return currentFirst && yearID == now
				? this.Current
				: this.Years.TryGetValue(yearID, out var year)
					? year
					: this.Years.TryAdd(yearID, year = new Year(yearID)) ? year : this.Years[yearID];
		}

		public Month GetMonth(string monthID, string yearID, bool currentFirst = true)
		{
			monthID ??= $"{DateTime.Now:MM}";
			var year = this.GetYear(yearID, currentFirst);
			return year.Months.TryGetValue(monthID, out var month)
				? month
				: year.Months.TryAdd(monthID, month = new Month(year.Name.As<int>(), monthID)) ? month : year.Months[monthID];
		}

		public Day GetDay(string dayID = null, string monthID = null, string yearID = null, bool currentFirst = true)
		{
			dayID ??= $"{DateTime.Now:dd}";
			var month = this.GetMonth(monthID, yearID, currentFirst);
			return month.Days.TryGetValue(dayID, out var day)
				? day
				: month.Days.TryAdd(dayID, day = new Day(dayID)) ? day : month.Days[dayID];
		}

		public int Get(string minuteID = null, string hourID = null, string dayID = null, string monthID = null, string yearID = null)
		{
			var hour = (hourID ?? $"{DateTime.Now:HH}").As<int>();
			var minute = (minuteID ?? $"{DateTime.Now:mm}").As<int>();
			var index = hour * 60 + minute;
			return index < 0 || index >= 1440 ? 0 : this.GetDay(dayID, monthID, yearID).Minutes[index];
		}

		public int Update(int counters = 0, string minuteID = null, string hourID = null, string dayID = null, string monthID = null, string yearID = null)
		{
			var day = this.GetDay(dayID, monthID, yearID);
			var hour = (hourID ?? $"{DateTime.Now:HH}").As<int>();
			var minute = (minuteID ?? $"{DateTime.Now:mm}").As<int>();
			var delta = counters > 0 ? day.Merge(hour, minute, counters) : day.Increase(hour, minute);
			if (delta > 0)
			{
				this.GetMonth(monthID, yearID).Increase(delta);
				this.GetYear(yearID).Increase(delta);
			}
			return delta;
		}

		public JObject ToJson(bool asSummary = false, bool addDayDetails = true, bool addHourDetails = true, Func<IEnumerable<Year>, JObject, JObject> transformer = null)
		{
			var years = this.Years.Values.OrderByDescending(year => year.Name).ToList();
			var json = new JObject();
			years.ForEach(year => json[year.Name] = year.ToJson(asSummary, addDayDetails, addHourDetails));
			return transformer != null ? transformer(years, json) : json;
		}

		public void SendStatistics(Action<int, string, string, string, string, string> sendStatistics)
		{
			foreach (var month in this.Current.Months.Values)
				foreach (var day in month.Days.Values)
					for (var hour = 0; hour < 24; hour++)
						for (var minute = 0; minute < 60; minute++)
							sendStatistics(day.Minutes[hour * 60 + minute], $"{minute:00}", $"{hour:00}", day.Name, month.Name, this.Current.Name);
		}

		Statistics Load(JObject hours, string dayID, string monthID, string yearID, bool currentFirst = true)
		{
			var day = this.GetDay(dayID, monthID, yearID, currentFirst);
			hours.ForEach(hour => (hour.Value as JObject).ForEach(minute => day.Set(hour.Key.As<int>(), minute.Key.As<int>(), (minute.Value as JValue ?? new JValue(0)).Value.As<int>())));
			return this;
		}

		Statistics Load(JObject json)
		{
			json?.ForEach(year => (year.Value as JObject).ForEach(month => (month.Value as JObject).ForEach(day => this.Load(day.Value as JObject, day.Key, month.Key, year.Key))));
			return this;
		}

		public async Task<Statistics> LoadAsync(string filePath, CancellationToken cancellationToken)
			=> File.Exists(filePath) ? this.Load(await UtilityService.ReadAsJsonAsync(filePath, cancellationToken).ConfigureAwait(false) as JObject) : this;

		async Task<Statistics> LoadAsync(bool current, CancellationToken cancellationToken)
		{
			var filter = current
				? Filters<Info>.And
				(
					Filters<Info>.Equals("Year", DateTime.Now.Year),
					Filters<Info>.Equals("Month", DateTime.Now.Month),
					Filters<Info>.Equals("Day", DateTime.Now.Day)
				)
				: null;
			var objects = await Info.FindAsync(filter, Sorts<Info>.Descending("Year").ThenByDescending("Month").ThenByDescending("Day"), 0, 1, null, cancellationToken).ConfigureAwait(false);
			objects?.ForEach(info => this.Load(info.Statistics.ToJson() as JObject, info.Day.ToString("00"), info.Month.ToString("00"), info.Year.ToString("0000"), current));
			return this;
		}

		public Task<Statistics> LoadAsync(CancellationToken cancellationToken)
			=> this.LoadAsync(true, cancellationToken);

		public async Task<Statistics> LoadStatisticsAsync(CancellationToken cancellationToken)
		{
			await this.LoadAsync(false, cancellationToken).ConfigureAwait(false);
			this.GetMonth(null, null, false).Days[$"{DateTime.Now:dd}"] = this.GetDay();
			return this;
		}

		public async Task<Statistics> SaveAsync(string filePath, CancellationToken cancellationToken)
		{
			await new JObject
			{
				[this.Current.Name] = this.Current.ToJson(false, true, true)
			}.SaveAsTextAsync(filePath, cancellationToken).ConfigureAwait(false);
			return this;
		}

		public async Task<Statistics> SaveAsync(CancellationToken cancellationToken)
		{
			var data = this.Current.Months.Values.Select(month => month.Days.Values.Select(day => (month.Year, Month: month.Name, Day: day))).SelectMany(info => info).ToList();
			await data.ForEachAsync(async info =>
			{
				var id = $"{info.Year}{info.Month}{info.Day.Name}{UtilityService.BlankUUID}".Left(32);
				var instance = await Info.GetAsync<Info>(id, cancellationToken).ConfigureAwait(false);
				var doUpdate = instance != null;
				instance ??= new()
				{
					ID = id,
					Year = info.Year,
					Month = info.Month.As<int>(),
					Day = info.Day.Name.As<int>()
				};
				instance.Statistics = info.Day.ToJson(false).ToString(Formatting.None);
				await (doUpdate ? Info.UpdateAsync(instance, true, cancellationToken) : Info.CreateAsync(instance, cancellationToken)).ConfigureAwait(false);
			}, true, false).ConfigureAwait(false);

			var thisDay = DateTime.Now.Day.ToString("00");
			var thisMonth = DateTime.Now.Month.ToString("00");

			this.Current.Months.Values.ForEach(month =>
			{
				if (month.Days.Count > 1)
				{
					var dayIDs = month.Days.Where(kvp => kvp.Key != thisDay).Select(kvp => kvp.Key).ToList();
					dayIDs.ForEach(dayID => month.Days.Remove(dayID));
					if (!month.Days.IsEmpty)
					{
						var currentMonth = this.GetMonth(month.Name, this.Current.Name, false);
						month.Days.ForEach(kvp => currentMonth.Days[kvp.Key] = kvp.Value);
					}
				}
			});

			if (this.Current.Months.Count > 1)
			{
				var months = this.Current.Months.Where(kvp => kvp.Key != thisMonth).Select(kvp => kvp.Key).ToList();
				months.ForEach(monthID => this.Current.Months.Remove(monthID));
				var day = this.Current.Months.First().Value.Days.First().Value;
				this.GetMonth(this.Current.Months.First().Value.Name, this.Current.Name, false).Days[day.Name] = day;
			}

			return this;
		}

		[BsonIgnoreExtraElements, DebuggerDisplay("Year = {Year}, Month = {Month}, Day = {Day}")]
		[Entity(CollectionName = "Statistics", TableName = "T_Users_Statistics", CacheClass = typeof(Utility), CacheName = "Cache", CreateNewVersionWhenUpdated = false)]
		public class Info : Repository<Info>
		{
			public Info() : base() { }
			[Sortable(IndexName = "Times")]
			public int Year { get; set; }
			[Sortable(IndexName = "Times")]
			public int Month { get; set; }
			[Sortable(IndexName = "Times")]
			public int Day { get; set; }
			[Property(IsCLOB = true)]
			public string Statistics { get; set; }
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
		}
	}
}