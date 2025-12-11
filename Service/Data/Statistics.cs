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

		internal Statistics(JObject json)
			=> this.Load(json);

		internal ConcurrentBag<Year> Years { get; } = [];

		public class Year : StatisticInfo
		{
			public Year() : this($"{DateTime.Now:yyyy}") { }

			internal Year(string yearID, int counters = 0) : base()
			{
				this.Name = yearID;
				this.Counters = counters;
			}

			internal ConcurrentBag<Month> Months { get; } = [];

			public int Sum(bool sumOnChildren = false)
				=> this.Counters = this.Months.Sum(month => sumOnChildren ? month.Sum(true) : month.Counters);

			internal JObject ToJson(bool asSummary, bool addDayDetails, bool addHourDetails)
			{
				var json = new JObject();
				this.Months.OrderBy(month => month.Name).ForEach(month => json[month.Name] = month.ToJson(asSummary, addDayDetails, addHourDetails));
				if (asSummary)
					json = new JObject
					{
						["Counters"] = this.Sum(),
						["AverageOfOneMonth"] = this.Counters / this.Months.Count,
						["Months"] = json
					};
				return json;
			}
		}

		public class Month : StatisticInfo
		{
			public Month() : this($"{DateTime.Now:MM}") { }

			internal Month(string monthID, int counters = 0) : base()
			{
				this.Name = monthID;
				this.Counters = counters;
			}

			internal ConcurrentBag<Day> Days { get; } = [];

			public int Sum(bool sumOnChildren = false)
				=> this.Counters = this.Days.Sum(day => sumOnChildren ? day.Sum(true) : day.Counters);

			internal JObject ToJson(bool asSummary, bool addDayDetails, bool addHourDetails)
			{
				var json = new JObject();
				this.Days.OrderBy(day => day.Name).ForEach(day => json[day.Name] = day.ToJson(asSummary, addHourDetails));
				if (asSummary)
				{
					json = new JObject
					{
						["Counters"] = this.Sum(),
						["AverageOfOneDay"] = this.Counters / this.Days.Count,
						["Days"] = json
					};
					if (!addDayDetails)
						json.Remove("Days");
				}
				return json;
			}
		}

		public class Day : StatisticInfo
		{
			public Day() : this($"{DateTime.Now:dd}") { }

			internal Day(string dayID, int counters = 0) : base()
			{
				this.Name = dayID;
				this.Counters = counters;
			}

			internal ConcurrentBag<Hour> Hours { get; } = [];

			public int Sum(bool sumOnChildren = false)
				=> this.Counters = this.Hours.Sum(hour => sumOnChildren ? hour.Sum() : hour.Counters);

			internal JObject ToJson(bool asSummary, bool addHourDetails = true)
			{
				var json = new JObject();
				this.Hours.OrderBy(hour => hour.Name).ForEach(hour => json[hour.Name] = hour.ToJson(asSummary));
				if (asSummary)
				{
					json = new JObject
					{
						["Counters"] = this.Sum(),
						["AverageOfOneHour"] = this.Counters / this.Hours.Count,
						["Hours"] = json
					};
					if (!addHourDetails)
						json.Remove("Hours");
				}
				return json;
			}
		}

		public class Hour : StatisticInfo
		{
			public Hour() : this($"{DateTime.Now:HH}") { }

			internal Hour(string hourID, int counters = 0) : base()
			{
				this.Name = hourID;
				this.Counters = counters;
			}

			internal ConcurrentBag<Minute> Minutes { get; } = [];

			public int Sum()
				=> this.Counters = this.Minutes.Sum(minute => minute.Counters);

			internal JObject ToJson(bool asSummary)
			{
				var json = new JObject();
				if (asSummary)
					json = new JObject
					{
						["Counters"] = this.Sum(),
						["AverageOfOneMinute"] = this.Counters / this.Minutes.Count
					};
				else
					this.Minutes.OrderBy(minute => minute.Name).ForEach(minute => json[minute.Name] = minute.Counters);
				return json;
			}
		}

		public class Minute : StatisticInfo
		{
			public Minute() : this($"{DateTime.Now:mm}") { }

			internal Minute(string minuteID, int counters = 0) : base()
			{
				this.Name = minuteID;
				this.Counters = counters;
			}

			internal Minute Update(int counters = 0)
			{
				this.Counters = counters > this.Counters ? counters : this.Counters + (counters == 0 ? 1 : 0);
				return this;
			}
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
			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
			public override string Title { get; set; }
			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
			public override string SystemID { get; set; }
			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
			public override string RepositoryID { get; set; }
			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
			public override string RepositoryEntityID { get; set; }
			[Ignore, JsonIgnore, BsonIgnore, XmlIgnore]
			public override Privileges OriginalPrivileges { get; set; }
		}

		public void SendStatistics(Action<int, string, string, string, string, string> sendStatistics)
			=> this.Years.ForEach(year => year.Months.ForEach(month => month.Days.ForEach(day => day.Hours.ForEach(hour => hour.Minutes.ForEach(minute => sendStatistics(minute.Counters, minute.Name, hour.Name, day.Name, month.Name, year.Name))))));

		void Load(JObject hours, string dayID, string monthID, string yearID)
			=> hours.ForEach(hour => (hour.Value as JObject).ForEach(minute => this.Update((minute.Value as JValue ?? new JValue(0)).Value.As<int>(), minute.Key, hour.Key, dayID, monthID, yearID)));

		public Statistics Load(JObject json)
		{
			this.Years.Clear();
			(json ?? new()).ForEach(year => (year.Value as JObject).ForEach(month => (month.Value as JObject).ForEach(day => this.Load(day.Value as JObject, day.Key, month.Key, year.Key))));
			return this;
		}

		public async Task<Statistics> LoadAsync(FileInfo fileInfo, CancellationToken cancellationToken)
			=> this.Load(await fileInfo.ReadAsJsonAsync(cancellationToken).ConfigureAwait(false) as JObject);

		public Task<Statistics> LoadAsync(string filePath, CancellationToken cancellationToken)
			=> this.LoadAsync(new FileInfo(filePath), cancellationToken);

		public async Task<Statistics> LoadAsync(CancellationToken cancellationToken)
		{
			var objects = await Info.FindAsync(null, Sorts<Info>.Descending("Year").ThenByDescending("Month").ThenByDescending("Day"), 0, 1, null, cancellationToken).ConfigureAwait(false);
			objects.ForEach(info => this.Load(info.Statistics.ToJson() as JObject, info.Day.ToString("00"), info.Month.ToString("00"), info.Year.ToString("0000")));
			return this;
		}

		public async Task<Statistics> SaveAsync(string filePath, CancellationToken cancellationToken)
		{
			await this.ToJson().SaveAsTextAsync(filePath, cancellationToken).ConfigureAwait(false);
			return this;
		}

		public async Task<Statistics> SaveAsync(CancellationToken cancellationToken)
		{
			await this.Years.OrderByDescending(year => year.Name).ForEachAsync(year => year.Months.OrderBy(month => month.Name).ForEachAsync(month => month.Days.OrderBy(day => day.Name).ForEachAsync(async day =>
			{
				var id = $"{year.Name}{month.Name}{day.Name}{UtilityService.BlankUUID}".Left(32);
				var info = await Info.GetAsync<Info>(id, cancellationToken).ConfigureAwait(false);
				var doUpdate = info != null;
				info ??= new()
				{
					ID = id,
					Year = year.Name.As<int>(),
					Month = month.Name.As<int>(),
					Day = day.Name.As<int>()
				};
				info.Statistics = day.ToJson(false).ToString(Formatting.None);
				await (doUpdate ? Info.UpdateAsync(info, true, cancellationToken) : Info.CreateAsync(info, cancellationToken)).ConfigureAwait(false);
			}, true, false), true, false), true, false).ConfigureAwait(false);
			return this;
		}

		public ulong Sum(bool sumOnChildren = true)
		{
			ulong sum = 0;
			this.Years.ForEach(year => sum += year.Sum(sumOnChildren).As<ulong>());
			return sum;
		}

		public JObject ToJson(bool asSummary = false, bool addDayDetails = true, bool addHourDetails = true, Func<IEnumerable<Year>, JObject, JObject> transformer = null)
		{
			var json = new JObject();
			this.Years.OrderByDescending(year => year.Name).ForEach(year => json[year.Name] = year.ToJson(asSummary, addDayDetails, addHourDetails));
			return transformer != null ? transformer(this.Years, json) : json;
		}

		public Minute Get(string minuteID = null, string hourID = null, string dayID = null, string monthID = null, string yearID = null)
		{
			yearID ??= $"{DateTime.Now:yyyy}";
			var year = this.Years.FirstOrDefault(o => o.Name == yearID);
			if (year == null)
				this.Years.Add(year = new(yearID));

			monthID ??= $"{DateTime.Now:MM}";
			var month = year.Months.FirstOrDefault(o => o.Name == monthID);
			if (month == null)
				year.Months.Add(month = new(monthID));

			dayID ??= $"{DateTime.Now:dd}";
			var day = month.Days.FirstOrDefault(o => o.Name == dayID);
			if (day == null)
				month.Days.Add(day = new(dayID));

			hourID ??= $"{DateTime.Now:HH}";
			var hour = day.Hours.FirstOrDefault(o => o.Name == hourID);
			if (hour == null)
				day.Hours.Add(hour = new(hourID));

			minuteID ??= $"{DateTime.Now:mm}";
			var minute = hour.Minutes.FirstOrDefault(o => o.Name == minuteID);
			if (minute == null)
				hour.Minutes.Add(minute = new(minuteID));

			return minute;
		}

		public Minute Update(int counters = 0, string minuteID = null, string hourID = null, string dayID = null, string monthID = null, string yearID = null)
			=> this.Get(minuteID, hourID, dayID, monthID, yearID).Update(counters);
	}

}