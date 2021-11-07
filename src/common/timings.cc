#include <string.h>
#include <errno.h>
#include <time.h>
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include "misc_log_ex.h"
#include "timings.h"

#define N_EXPECTED_FIELDS (8+11)

TimingsDatabase::TimingsDatabase()
{
}

TimingsDatabase::TimingsDatabase(const std::string &filename, const bool load_previous /*=false*/):
  filename(filename)
{
  if (load_previous)
    load();
}

TimingsDatabase::~TimingsDatabase()
{
  save();
}

bool TimingsDatabase::load()
{
  instances.clear();

  if (filename.empty())
    return true;

  FILE *f = fopen(filename.c_str(), "r");
  if (!f)
  {
    MDEBUG("Failed to load timings file " << filename << ": " << strerror(errno));
    return false;
  }
  while (1)
  {
    char s[4096];
    if (!fgets(s, sizeof(s), f))
      break;
    char *tab = strchr(s, '\t');
    if (!tab)
    {
      MWARNING("Bad format: no tab found");
      continue;
    }
    const std::string name = std::string(s, tab - s);
    std::vector<std::string> fields;
    char *ptr = tab + 1;
    boost::split(fields, ptr, boost::is_any_of(" "));
    if (fields.size() != N_EXPECTED_FIELDS)
    {
      MERROR("Bad format: wrong number of fields: got " << fields.size() << " expected " << N_EXPECTED_FIELDS);
      continue;
    }

    instance i;

    unsigned int idx = 0;
    i.t = atoi(fields[idx++].c_str());
    i.npoints = atoi(fields[idx++].c_str());
    i.min = atof(fields[idx++].c_str());
    i.max = atof(fields[idx++].c_str());
    i.mean = atof(fields[idx++].c_str());
    i.median = atof(fields[idx++].c_str());
    i.stddev = atof(fields[idx++].c_str());
    i.npskew = atof(fields[idx++].c_str());
    i.deciles.reserve(11);
    for (int n = 0; n < 11; ++n)
    {
      i.deciles.push_back(atoi(fields[idx++].c_str()));
    }
    instances.emplace_back(name, i);
  }
  fclose(f);
  return true;
}

bool TimingsDatabase::save(const bool print_current_time /*=true*/)
{
  if (filename.empty() || instances.empty())
    return true;

  FILE *f = fopen(filename.c_str(), "a");  // append
  if (!f)
  {
    MERROR("Failed to write to file " << filename << ": " << strerror(errno));
    return false;
  }

  if (print_current_time)
  {
    // print current time in readable format (UTC)
    std::time_t sys_time{std::time(nullptr)};
    std::tm *utc_time = std::gmtime(&sys_time);    //GMT /equiv UTC

    // format: year-month-day : hour:minute:second
    std::string current_time{};
    if (utc_time && sys_time != (std::time_t)(-1))
    {
        current_time += std::to_string(utc_time->tm_year + 1900) + '-';
        current_time += (std::to_string(utc_time->tm_mon + 1).size() == 1 ? std::string{'0'} : std::string{}) +
          std::to_string(utc_time->tm_mon + 1) + '-';
        current_time += (std::to_string(utc_time->tm_mday).size() == 1 ? std::string{'0'} : std::string{}) +
          std::to_string(utc_time->tm_mday) + " : ";
        current_time += (std::to_string(utc_time->tm_hour).size() == 1 ? std::string{'0'} : std::string{}) +
          std::to_string(utc_time->tm_hour) + ':';
        current_time += (std::to_string(utc_time->tm_min).size() == 1 ? std::string{'0'} : std::string{}) +
          std::to_string(utc_time->tm_min) + ':';
        current_time += (std::to_string(utc_time->tm_sec).size() == 1 ? std::string{'0'} : std::string{}) +
          std::to_string(utc_time->tm_sec);
    }
    else
    {
        current_time += "TIME_ERROR_";
    }
    fputc('\n', f);  // add an extra line before each 'print time'
    fprintf(f, "%s", current_time.c_str());
    fputc('\n', f);
  }

  for (const auto &i: instances)
  {
    fprintf(f, "%s,", i.first.c_str());

    if (i.second.npoints > 0)
    {
      fprintf(f, "%lu,", (unsigned long)i.second.t);
      fprintf(f, "%zu,", i.second.npoints);
      fprintf(f, "%f,", i.second.min);
      fprintf(f, "%f,", i.second.max);
      fprintf(f, "%f,", i.second.mean);
      fprintf(f, "%f,", i.second.median);
      fprintf(f, "%f,", i.second.stddev);
      fprintf(f, "%f,", i.second.npskew);
      for (uint64_t v: i.second.deciles)
        fprintf(f, "%lu,", (unsigned long)v);
      fputc('\n', f);  // only add new line if there are points; assume that 'no points' means i.first is for prepending
    }
  }
  fclose(f);

  // after saving, clear so next save does not append the same stuff over again
  instances.clear();

  return true;
}

/*
std::vector<TimingsDatabase::instance> TimingsDatabase::get(const char *name) const
{
  std::vector<instance> ret;
  auto range = instances.equal_range(name);
  for (auto i = range.first; i != range.second; ++i)
    ret.push_back(i->second);
  std::sort(ret.begin(), ret.end(), [](const instance &e0, const instance &e1){ return e0.t < e1.t; });
  return ret;
}
*/

void TimingsDatabase::add(const char *name, const instance &i)
{
  instances.emplace_back(name, i);
}
