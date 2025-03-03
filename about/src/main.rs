use prettytable::{Table, Row, Cell};

fn main() {
println!("    
                                                                                    
                                                                                        
                ▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒                                
              ▒▒▒▒▒▒                ▒▒▒▒▒▒                              
              ▒▒▒▒▒▒▒▒▒▒        ▒▒▒▒▒▒▒▒▒▒                              
            ▒▒▒▒▒▒▒▒▒▒            ▒▒▒▒▒▒▒▒▒▒                            
            ▒▒▒▒      ██        ██      ▒▒▒▒                            
            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            
            ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                            
              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              
                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  
              ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                              
            ▒▒▒▒    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒    ▒▒▒▒                            
                  ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                  
                ▒▒▒▒    ▒▒▒▒▒▒▒▒    ▒▒▒▒                                

            https://bakerstreetforensics.com  
\n");    
    println!("MalChela - A YARA & Malware Analysis Toolkit written in Rust\n");
    println!("ABOUT:");
    println!("  mal — malware");
    println!("  chela — \"crab hand\"\n");
    println!("A chela on a crab is the scientific term for a claw or pincer. It’s a specialized appendage, typically found on the first pair of legs, used for grasping, defense, and manipulating things; just like these programs.\n");

    println!("FEATURES:");

    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Feature"),
        Cell::new("Description"),
    ]));

    table.add_row(Row::new(vec![
        Cell::new("Combine YARA"),
        Cell::new("Point it at a directory of YARA files and it will output one combined rule"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("Extract Samples"),
        Cell::new("Point it at a directory of password protected malware files to extract all"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("Hash It"),
        Cell::new("Point it to a file and get the MD5, SHA1 and SHA256 hash"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("MZMD5"),
        Cell::new("Recurse a directory, for files with MZ header, create hash list"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("MZcount"),
        Cell::new("Recurse a directory, uses YARA to count MZ, Zip, PDF, other"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("NSRL MD5 Lookup"),
        Cell::new("Query an MD5 hash against NSRL"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("NSRL SHA1 Lookup"),
        Cell::new("Query a SHA1 hash against NSRL"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("Strings to YARA"),
        Cell::new("Prompts for metadata and strings (text file) to create a YARA rule"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("Malware Hash Lookup"),
        Cell::new("Query a hash value against VirusTotal & Malware Bazaar*"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("XMZMD5"),
        Cell::new("Recurse a directory, for files without MZ, Zip or PDF header, create hash list"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("About"),
        Cell::new("You are here"),
    ]));

    table.printstd();

    println!(
        "\n*The Malware Hash Lookup requires an API key for VirusTotal and Malware Bazaar. If unidentified, MalChela will prompt you to create them the first time you run the malware lookup function."
    );
    println!(); 

}
