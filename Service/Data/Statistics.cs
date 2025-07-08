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
		static bool UseJObject { get; } = "json".IsEquals(UtilityService.GetAppSetting("Sessions:Type", "BAG"));

		JObject Data { get; set; } = new();

		ConcurrentBag<Year> Years { get; set; } = [];

		public Statistics() { }

		public Statistics(JObject statistics)
			=> this.Parse(statistics);

		public class Year : StatisticInfo
		{
			public Year() : this($"{DateTime.Now:yyyy}") { }
			public Year(string yearID, int total = 0) : base()
			{
				this.Name = yearID;
				this.Counters = total;
			}
			public ConcurrentBag<Month> Months { get; set; } = [];
			public JObject ToJson(bool asSummary, bool addHourDetails)
			{
				var json = new JObject();
				this.Months.OrderBy(month => month.Name).ForEach(month => json[month.Name] = month.ToJson(asSummary, addHourDetails));
				if (asSummary)
				{
					this.Counters = this.Months.Sum(month => month.Counters);
					json = new JObject
					{
						["Total"] = this.Counters,
						["AverageOfOneMonth"] = this.Counters / this.Months.Count,
						["Months"] = json
					};
				}
				return json;
			}
		}

		public class Month : StatisticInfo
		{
			public Month() : this($"{DateTime.Now:MM}") { }
			public Month(string monthID, int total = 0) : base()
			{
				this.Name = monthID;
				this.Counters = total;
			}
			public ConcurrentBag<Day> Days { get; set; } = [];
			public JObject ToJson(bool asSummary, bool addHourDetails)
			{
				var json = new JObject();
				this.Days.OrderBy(day => day.Name).ForEach(day => json[day.Name] = day.ToJson(asSummary, addHourDetails));
				if (asSummary)
				{
					this.Counters = this.Days.Sum(day => day.Counters);
					json = new JObject
					{
						["Total"] = this.Counters,
						["AverageOfOneDay"] = this.Counters / this.Days.Count,
						["Days"] = json
					};
				}
				return json;
			}
		}

		public class Day : StatisticInfo
		{
			public Day() : this($"{DateTime.Now:dd}") { }
			public Day(string dayID, int total = 0) : base()
			{
				this.Name = dayID;
				this.Counters = total;
			}
			public ConcurrentBag<Hour> Hours { get; set; } = [];
			public JObject ToJson(bool asSummary, bool addHourDetails)
			{
				var json = new JObject();
				this.Hours.OrderBy(hour => hour.Name).ForEach(hour => json[hour.Name] = hour.ToJson(asSummary));
				if (asSummary)
				{
					this.Counters = this.Hours.Sum(hour => hour.Counters);
					json = new JObject
					{
						["Total"] = this.Counters,
						["AverageOfOneHour"] = this.Counters / this.Hours.Count,
						["Hours"] = addHourDetails ? json : null
					};
				}
				return json;
			}
		}

		public class Hour : StatisticInfo
		{
			public Hour() : this($"{DateTime.Now:HH}") { }
			public Hour(string hourID, int total = 0) : base()
			{
				this.Name = hourID;
				this.Counters = total;
			}
			public ConcurrentBag<Minute> Minutes { get; set; } = [];
			public JObject ToJson(bool asSummary)
			{
				var json = new JObject();
				if (asSummary)
				{
					this.Counters = this.Minutes.Sum(minute => minute.Counters);
					json = new JObject
					{
						["Total"] = this.Counters,
						["AverageOfOneMinute"] = this.Counters / this.Minutes.Count
					};
				}
				else
					this.Minutes.OrderBy(minute => minute.Name).ForEach(minute => json[minute.Name] = minute.Counters);
				return json;
			}
		}

		public class Minute : StatisticInfo
		{
			public Minute() : this($"{DateTime.Now:mm}") { }
			public Minute(string minuteID, int total = 0) : base()
			{
				this.Name = minuteID;
				this.Counters = total;
			}
		}

		JObject Normalize(JObject data)
		{
			var years = new Dictionary<string, JObject>();
			(data ?? new()).ForEach(kvpYear =>
			{
				var yearID = kvpYear.Key;
				var yearJson = kvpYear.Value as JObject;
				var months = new Dictionary<string, JObject>();
				yearJson.ForEach(kvpMonth =>
				{
					var monthID = kvpMonth.Key;
					var monthJson = kvpMonth.Value as JObject;
					var days = new Dictionary<string, JObject>();
					monthJson.ForEach(kvpDay =>
					{
						var dayID = kvpDay.Key;
						var dayJson = kvpDay.Value as JObject;
						var hours = new Dictionary<string, JObject>();
						dayJson.ForEach(kvpHour =>
						{
							var hourID = kvpHour.Key;
							var hourJson = kvpHour.Value as JObject;
							var minutes = new Dictionary<string, JValue>();
							hourJson.ForEach(kvpMinute => minutes[kvpMinute.Key] = kvpMinute.Value as JValue ?? new JValue(0));
							hours[hourID] = minutes.OrderBy(kvp => kvp.Key).ToDictionary().ToJObject();
						});
						days[dayID] = hours.OrderBy(kvp => kvp.Key).ToDictionary().ToJObject();
					});
					months[monthID] = days.OrderBy(kvp => kvp.Key).ToDictionary().ToJObject();
				});
				years[yearID] = months.OrderBy(kvp => kvp.Key).ToDictionary().ToJObject();
			});
			return years.OrderBy(kvp => kvp.Key).ToDictionary().ToJObject();
		}

		void Parse(JObject data, Action<int, string, string, string, string, string> onNext)
			=> data.ForEach(kvpYear =>
			{
				var yearID = kvpYear.Key;
				var yearJson = kvpYear.Value as JObject;
				yearJson.ForEach(kvpMonth =>
				{
					var monthID = kvpMonth.Key;
					var monthJson = kvpMonth.Value as JObject;
					monthJson.ForEach(kvpDay =>
					{
						var dayID = kvpDay.Key;
						var dayJson = kvpDay.Value as JObject;
						dayJson.ForEach(kvpHour =>
						{
							var hourID = kvpHour.Key;
							var hourJson = kvpHour.Value as JObject;
							hourJson.ForEach(kvpMinute =>
							{
								var minuteID = kvpMinute.Key;
								var total = (kvpMinute.Value as JValue ?? new JValue(0)).Value.As<int>();
								onNext(total, minuteID, hourID, dayID, monthID, yearID);
							});
						});
					});
				});
			});

		public void Parse(JObject data)
		{
			this.Years = [];
			if (UseJObject)
				this.Data = this.Normalize(data);
			else
				this.Parse(data ?? new(), this.Update);
		}

		public async Task LoadAsync(string filePath, CancellationToken cancellationToken)
			=> this.Parse(await new FileInfo(filePath).ReadAsJsonAsync(cancellationToken).ConfigureAwait(false) as JObject);

		public JObject ToJson(bool asSummary = false, bool addHourDetails = true)
		{
			var json = new JObject();
			if (UseJObject)
			{
				if (asSummary)
					this.Normalize(this.Data).ForEach(kvpYear =>
					{
						var year = kvpYear.Value as JObject;
						var months = new Dictionary<string, JObject>();
						var totalOfTheYear = 0;
						year.ForEach(kvpMonth =>
						{
							var month = kvpMonth.Value as JObject;
							var days = new Dictionary<string, JObject>();
							var totalOfTheMonth = 0;
							month.ForEach(kvpDay =>
							{
								var day = kvpDay.Value as JObject;
								var hours = new Dictionary<string, JObject>();
								var totalOfTheDay = 0;
								day.ForEach(kvpHour =>
								{
									var totalOfTheHour = 0;
									var counterOfTheHour = 0;
									(kvpHour.Value as JObject).ForEach(kvpMinute =>
									{
										totalOfTheHour += (kvpMinute.Value as JValue).Value.As<int>();
										counterOfTheHour++;
									});
									hours[kvpHour.Key] = new JObject
									{
										["Total"] = totalOfTheHour,
										["AverageOfOneMinute"] = totalOfTheHour / counterOfTheHour
									};
									totalOfTheDay += totalOfTheHour;
								});
								days[kvpDay.Key] = new JObject
								{
									["Total"] = totalOfTheDay,
									["AverageOfOneHour"] = totalOfTheDay / hours.Count,
									["Hours"] = addHourDetails ? hours.ToJObject() : null
								};
								totalOfTheMonth += totalOfTheDay;
							});
							months[kvpMonth.Key] = new JObject
							{
								["Total"] = totalOfTheMonth,
								["AverageOfOneDay"] = totalOfTheMonth / days.Count,
								["Days"] = days.ToJObject()
							};
							totalOfTheYear += totalOfTheMonth;
						});
						json[kvpYear.Key] = new JObject
						{
							["Total"] = totalOfTheYear,
							["AverageOfOneMonth"] = totalOfTheYear / months.Count,
							["Months"] = months.ToJObject()
						};
					});
				else
					json = this.Normalize(this.Data);
			}
			else
				this.Years.OrderBy(year => year.Name).ForEach(year => json[year.Name] = year.ToJson(asSummary, addHourDetails));
			return json;
		}

		public Minute Get(string yearID = null, string monthID = null, string dayID = null, string hourID = null, string minuteID = null, int total = -1)
		{
			yearID ??= $"{DateTime.Now:yyyy}";
			monthID ??= $"{DateTime.Now:MM}";
			dayID ??= $"{DateTime.Now:dd}";
			hourID ??= $"{DateTime.Now:HH}";
			minuteID ??= $"{DateTime.Now:mm}";

			if (UseJObject)
			{
				var year = this.Data.Get<JObject>(yearID);
				if (year == null)
					this.Data[yearID] = year = new JObject();

				var month = year.Get<JObject>(monthID);
				if (month == null)
					year[monthID] = month = new JObject();

				var day = month.Get<JObject>(dayID);
				if (day == null)
					month[dayID] = day = new JObject();

				var hour = day.Get<JObject>(hourID);
				if (hour == null)
					day[hourID] = hour = new JObject();

				var minute = hour.Get<JValue>(minuteID);
				if (minute != null && total == 0)
					total = minute.Value.As<int>() + 1;
				hour[minuteID] = new JValue(total > 0 ? total : (minute ?? new JValue(1)).Value.As<int>());

				return new(minuteID, total);
			}
			else
			{
				var year = this.Years.FirstOrDefault(o => o.Name == yearID);
				if (year == null)
					this.Years.Add(year = new(yearID));

				var month = year.Months.FirstOrDefault(o => o.Name == monthID);
				if (month == null)
					year.Months.Add(month = new(monthID));

				var day = month.Days.FirstOrDefault(o => o.Name == dayID);
				if (day == null)
					month.Days.Add(day = new(dayID));

				var hour = day.Hours.FirstOrDefault(o => o.Name == hourID);
				if (hour == null)
					day.Hours.Add(hour = new(hourID));

				var minute = hour.Minutes.FirstOrDefault(o => o.Name == minuteID);
				if (minute == null)
					hour.Minutes.Add(minute = new(minuteID, total > 0 ? total : 0));

				return minute;
			}
		}

		public void Update(int total = 0, string minuteID = null, string hourID = null, string dayID = null, string monthID = null, string yearID = null)
		{
			var minute = this.Get(yearID, monthID, dayID, hourID, minuteID, UseJObject ? total : -1);
			if (!UseJObject)
				minute.Counters = total == 0 ? minute.Counters + 1 : total > minute.Counters ? total : minute.Counters;
		}

		public void SendStatistics(Action<int, string, string, string, string, string> sendStatistics)
		{
			if (UseJObject)
				this.Parse(this.Data, (total, minuteID, hourID, dayID, monthID, yearID) => sendStatistics(total, minuteID, hourID, dayID, monthID, yearID));
			else
				this.Years.ForEach(year => year.Months.ForEach(month => month.Days.ForEach(day => day.Hours.ForEach(hour => hour.Minutes.ForEach(minute => sendStatistics(minute.Counters, minute.Name, hour.Name, day.Name, month.Name, year.Name))))));
		}
	}

}