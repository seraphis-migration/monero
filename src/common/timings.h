#pragma once

#include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class TimingsDatabase
{
public:
  struct instance
  {
    time_t t;
    size_t npoints;
    double min, max, mean, median, stddev, npskew;
    std::vector<uint64_t> deciles;
  };

public:
  TimingsDatabase();
  TimingsDatabase(const std::string &filename, const bool load_previous = false);
  ~TimingsDatabase();

  //std::vector<instance> get(const char *name) const;  //changed to std::list from std::multimap... can't get range
  void add(const char *name, const instance &data);
  bool save(const bool print_current_time = true);

private:
  bool load();

private:
  std::string filename;
  std::list<std::pair<std::string, instance>> instances;
};
