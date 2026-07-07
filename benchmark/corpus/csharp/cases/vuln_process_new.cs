using System.Diagnostics;

public class Runner
{
    public void Convert(string userFile)
    {
        var process = new Process(); // ZS-CS-008: instance-based Process
        process.StartInfo.FileName = "convert.exe";
        process.StartInfo.Arguments = userFile;
        process.Start();
    }
}
