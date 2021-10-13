using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Whois.NET;

namespace MassDomainChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            static async Task Main()
            {
                var regex = new Regex("Status: free", RegexOptions.Compiled);

                var domains = ShortDomains(3, "de");

                foreach (var d in domains)
                {
                    var result = await WhoisClient.QueryAsync(d);

                    Console.WriteLine("{0}", result.Raw);

                    if (regex.IsMatch(result.Raw) == true)
                    {
                        await File.AppendAllTextAsync("free-domains.txt", result.Raw);
                    }
                }
            }

            static List<string> ShortDomains(int chars, string tld)
            {
                string allowedCharacters = "";
                for (char a = 'a'; a <= 'z'; a++)
                {
                    allowedCharacters += a;
                }
                for (char a = '0'; a <= '9'; a++)
                {
                    allowedCharacters += a;
                }

                List<string> domains = new();
                var currentChars = new char[chars];

                for (int i = 0; i < chars; i++)
                {
                    currentChars[i] = 'a';
                }

                while (currentChars.Any(x => x != allowedCharacters.Last()) == true)
                {
                    domains.Add(new string(currentChars) + "." + tld);

                    for (int i = currentChars.Length - 1; i >= 0; i--)
                    {
                        var currentIndex = allowedCharacters.IndexOf(currentChars[i]);
                        if (currentIndex == allowedCharacters.Length - 1)
                        {
                            currentChars[i] = allowedCharacters.First();
                            continue;
                        }
                        else
                        {
                            currentChars[i] = allowedCharacters[currentIndex + 1];
                            break;
                        }
                    }
                }

                return domains;
            }
        }

        static void FilterList()
        {
            File.WriteAllLines("justdomains.txt", new Regex(@"Domain: (?<Domain>([a-z]{3}\.de))", RegexOptions.Compiled).Matches(File.ReadAllText("3char-domains.txt")).OfType<Match>().Select(x => x.Groups["Domain"].Value));
        }
    }
}
