<?php
if( isset( $_REQUEST[ 'Submit' ] ) ) {
	// Get input
	$id = $_REQUEST[ 'id' ];
	
	// ===== SECURITY FIX #1: INPUT VALIDATION =====
	// Validate that ID is numeric to prevent injection
	if( !is_numeric( $id ) ) {
		$html .= "<pre style='color: red;'>Error: User ID must be a number</pre>";
	} else if( $id < 0 ) {
		$html .= "<pre style='color: red;'>Error: User ID must be positive</pre>";
	} else {
		// Proceed with database query using PREPARED STATEMENTS
		switch ($_DVWA['SQLI_DB']) {
			case MYSQL:
				// ===== SECURITY FIX #2: USE PREPARED STATEMENTS (MySQLi) =====
				// Instead of concatenating user input into query,
				// we use placeholders (?) and bind parameters separately
				
				// Prepare the statement with placeholder
				$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], 
					"SELECT first_name, last_name FROM users WHERE user_id = ?"
				);
				
				if ($stmt === false) {
					// Handle prepare error
					$html .= "<pre style='color: red;'>Error: Failed to prepare statement</pre>";
				} else {
					// ===== SECURITY FIX #3: BIND PARAMETERS =====
					// "i" means integer type - ensures $id is treated as number only
					// This prevents any SQL injection attacks
					mysqli_stmt_bind_param($stmt, "i", $id);
					
					// Execute the prepared statement
					if (!mysqli_stmt_execute($stmt)) {
						$html .= "<pre style='color: red;'>Error: " . mysqli_error($GLOBALS["___mysqli_ston"]) . "</pre>";
					} else {
						// Get results from prepared statement
						$result = mysqli_stmt_get_result($stmt);
						
						// Check if any rows were returned
						if (mysqli_num_rows($result) == 0) {
							$html .= "<pre>No records found for User ID: " . htmlspecialchars($id, ENT_QUOTES, 'UTF-8') . "</pre>";
						} else {
							// Get results
							while( $row = mysqli_fetch_assoc( $result ) ) {
								// Get values
								$first = $row["first_name"];
								$last  = $row["last_name"];
								
								// ===== SECURITY FIX #4: OUTPUT ENCODING =====
								// Encode output to prevent XSS attacks
								$first_safe = htmlspecialchars($first, ENT_QUOTES, 'UTF-8');
								$last_safe = htmlspecialchars($last, ENT_QUOTES, 'UTF-8');
								$id_safe = htmlspecialchars($id, ENT_QUOTES, 'UTF-8');
								
								// Feedback for end user
								$html .= "<pre>ID: {$id_safe}<br />First name: {$first_safe}<br />Surname: {$last_safe}</pre>";
							}
						}
					}
					
					// Close the prepared statement
					mysqli_stmt_close($stmt);
				}
				
				mysqli_close($GLOBALS["___mysqli_ston"]);
				break;
				
			case SQLITE:
				global $sqlite_db_connection;
				
				// ===== SECURITY FIX #5: SQLite PREPARED STATEMENTS =====
				try {
					// Prepare statement with placeholder (:id)
					$stmt = $sqlite_db_connection->prepare(
						"SELECT first_name, last_name FROM users WHERE user_id = :id"
					);
					
					if ($stmt === false) {
						$html .= "<pre style='color: red;'>Error: Failed to prepare statement</pre>";
					} else {
						// Bind the parameter (forces type safety)
						$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
						
						// Execute the prepared statement
						$results = $stmt->execute();
						
						if ($results === false) {
							$html .= "<pre style='color: red;'>Error: Query execution failed</pre>";
						} else {
							// Check if results exist
							$row_count = 0;
							
							while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
								$row_count++;
								
								// Get values
								$first = $row["first_name"];
								$last  = $row["last_name"];
								
								// Output encoding for XSS prevention
								$first_safe = htmlspecialchars($first, ENT_QUOTES, 'UTF-8');
								$last_safe = htmlspecialchars($last, ENT_QUOTES, 'UTF-8');
								$id_safe = htmlspecialchars($id, ENT_QUOTES, 'UTF-8');
								
								// Feedback for end user
								$html .= "<pre>ID: {$id_safe}<br />First name: {$first_safe}<br />Surname: {$last_safe}</pre>";
							}
							
							if ($row_count == 0) {
								$html .= "<pre>No records found for User ID: " . htmlspecialchars($id, ENT_QUOTES, 'UTF-8') . "</pre>";
							}
						}
					}
					
				} catch (Exception $e) {
					$html .= "<pre style='color: red;'>Caught exception: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</pre>";
				}
				break;
		}
	}
}
?>
