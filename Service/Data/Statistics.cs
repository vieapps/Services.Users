#region Related components
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Users
{
	public class Statistics
	{
		public Statistics() { }

		public Statistics(JObject json)
			=> this.Load(json);

		ConcurrentBag<Year> Years { get; } = [];

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
			{
				if (sumOnChildren)
					this.Months.ForEach(month => month.Sum(true));
				return this.Counters = this.Months.Sum(month => month.Counters);
			}

			internal JObject ToJson(bool asSummary, bool addHourDetails)
			{
				var json = new JObject();
				this.Months.OrderBy(month => month.Name).ForEach(month => json[month.Name] = month.ToJson(asSummary, addHourDetails));
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
			{
				if (sumOnChildren)
					this.Days.ForEach(day => day.Sum(true));
				return this.Counters = this.Days.Sum(day => day.Counters);
			}

			internal JObject ToJson(bool asSummary, bool addHourDetails)
			{
				var json = new JObject();
				this.Days.OrderBy(day => day.Name).ForEach(day => json[day.Name] = day.ToJson(asSummary, addHourDetails));
				if (asSummary)
					json = new JObject
					{
						["Counters"] = this.Sum(),
						["AverageOfOneDay"] = this.Counters / this.Days.Count,
						["Days"] = json
					};
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
			{
				if (sumOnChildren)
					this.Hours.ForEach(hour => hour.Sum());
				return this.Counters = this.Hours.Sum(hour => hour.Counters);
			}

			internal JObject ToJson(bool asSummary, bool addHourDetails)
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

			internal void Update(int counters = 0)
				=> this.Counters = counters > this.Counters ? counters : this.Counters + (counters == 0 ? 1 : 0);
		}

		public Statistics Load(JObject json)
		{
			this.Years.Clear();
			(json ?? new()).ForEach(year =>
			{
				var yearID = year.Key;
				var yearJson = year.Value as JObject;
				yearJson.ForEach(month =>
				{
					var monthID = month.Key;
					var monthJson = month.Value as JObject;
					monthJson.ForEach(day =>
					{
						var dayID = day.Key;
						var dayJson = day.Value as JObject;
						dayJson.ForEach(hour =>
						{
							var hourID = hour.Key;
							var hourJson = hour.Value as JObject;
							hourJson.ForEach(minute =>
							{
								var minuteID = minute.Key;
								var counters = (minute.Value as JValue ?? new JValue(0)).Value.As<int>();
								this.Update(counters, minuteID, hourID, dayID, monthID, yearID);
							});
						});
					});
				});
			});
			return this;
		}

		public async Task<Statistics> LoadAsync(FileInfo fileInfo, CancellationToken cancellationToken)
			=> this.Load(await fileInfo.ReadAsJsonAsync(cancellationToken).ConfigureAwait(false) as JObject);

		public Task<Statistics> LoadAsync(string filePath, CancellationToken cancellationToken)
			=> this.LoadAsync(new FileInfo(filePath), cancellationToken);

		public JObject ToJson(IEnumerable<int> years, bool asSummary = false, bool addHourDetails = true)
		{
			var json = new JObject();
			(years != null ? this.Years.Where(year => years.Any(y => y.ToString("####") == year.Name)) : this.Years).OrderBy(year => year.Name).ForEach(year => json[year.Name] = year.ToJson(asSummary, addHourDetails));
			return json;
		}

		public JObject ToJson(bool asSummary = false, bool addHourDetails = true, IEnumerable<DateTime> years = null)
			=> this.ToJson(years?.Select(time => time.Year).Distinct(), asSummary, addHourDetails);

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

		public void Update(int counters = 0, string minuteID = null, string hourID = null, string dayID = null, string monthID = null, string yearID = null)
			=> this.Get(minuteID, hourID, dayID, monthID, yearID).Update(counters);

		public void SendStatistics(Action<int, string, string, string, string, string> sendStatistics)
			=> this.Years.ForEach(year => year.Months.ForEach(month => month.Days.ForEach(day => day.Hours.ForEach(hour => hour.Minutes.ForEach(minute => sendStatistics(minute.Counters, minute.Name, hour.Name, day.Name, month.Name, year.Name))))));
	}

}