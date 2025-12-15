from parser import parse_log_file

if __name__ == "__main__":
    for event in parse_log_file("samples/auth.log"):
        print(event)
