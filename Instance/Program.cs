using System;

namespace net.vieapps.Services.Users
{
	class Program
	{
		static void Main(string[] args)
		{
			using (var serviceComponent = new ServiceComponent())
			{
				serviceComponent.Start(args);
				Console.ReadLine();
			}
		}
	}
}