import { google } from 'googleapis';

/**
 * Initialize Google Sheets API client with service account credentials
 */
const getSheetsClient = () => {
  try {
    // Validate required environment variables
    if (!process.env.GOOGLE_PROJECT_ID) {
      throw new Error('GOOGLE_PROJECT_ID environment variable is not set');
    }
    if (!process.env.GOOGLE_CLIENT_EMAIL) {
      throw new Error('GOOGLE_CLIENT_EMAIL environment variable is not set');
    }
    if (!process.env.GOOGLE_PRIVATE_KEY) {
      throw new Error('GOOGLE_PRIVATE_KEY environment variable is not set');
    }

    // Build credentials object
    const credentials = {
      type: 'service_account',
      project_id: process.env.GOOGLE_PROJECT_ID,
      private_key_id: process.env.GOOGLE_PRIVATE_KEY_ID,
      private_key: process.env.GOOGLE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
      client_email: process.env.GOOGLE_CLIENT_EMAIL,
      auth_uri: 'https://accounts.google.com/o/oauth2/auth',
      token_uri: 'https://oauth2.googleapis.com/token',
      auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
      client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.GOOGLE_CLIENT_EMAIL || '')}`,
    };

    // Add client_id if available (optional for service accounts)
    if (process.env.GOOGLE_CLIENT_ID) {
      credentials.client_id = process.env.GOOGLE_CLIENT_ID;
    }

    const auth = new google.auth.GoogleAuth({
      credentials,
      scopes: ['https://www.googleapis.com/auth/spreadsheets'],
    });

    const sheets = google.sheets({ version: 'v4', auth });
    return sheets;
  } catch (error) {
    console.error('[GOOGLE SHEETS] Error initializing client:', error);
    error.status = 500;
    throw error;
  }
};

/**
 * Get the spreadsheet ID from environment variable
 */
const getSpreadsheetId = () => {
  const sheetId = process.env.SHEET_ID;
  if (!sheetId) {
    throw new Error('SHEET_ID environment variable is not set');
  }
  return sheetId;
};

/**
 * Get or create the main sheet with headers
 */
const ensureSheetExists = async (sheets, spreadsheetId, sheetName = 'Submissions') => {
  try {
    // Try to get the sheet
    let spreadsheet;
    try {
      spreadsheet = await sheets.spreadsheets.get({
        spreadsheetId,
      });
    } catch (error) {
      if (error.code === 403 || error.code === 404) {
        const err = new Error(
          `Access denied or spreadsheet not found. Please ensure the spreadsheet is shared with the service account: ${process.env.GOOGLE_CLIENT_EMAIL}`
        );
        err.status = 403;
        err.code = error.code;
        throw err;
      }
      error.status = error.status || 500;
      throw error;
    }

    const sheetExists = spreadsheet.data.sheets?.some(
      (sheet) => sheet.properties.title === sheetName
    );

    if (!sheetExists) {
      // Create the sheet
      await sheets.spreadsheets.batchUpdate({
        spreadsheetId,
        requestBody: {
          requests: [
            {
              addSheet: {
                properties: {
                  title: sheetName,
                },
              },
            },
          ],
        },
      });

      // Add headers
      await sheets.spreadsheets.values.update({
        spreadsheetId,
        range: `${sheetName}!A1:J1`,
        valueInputOption: 'RAW',
        requestBody: {
          values: [
            [
              'Submission Time',
              'Team name',
              'Team id',
              'Leader name',
              'Leader\'s phone',
              'Leader\'s email',
              'Github link',
              'PPT link',
              'Video link',
              'Description',
            ],
          ],
        },
      });
    } else {
      // Check if headers exist
      const headerRange = await sheets.spreadsheets.values.get({
        spreadsheetId,
        range: `${sheetName}!A1:J1`,
      });

      if (!headerRange.data.values || headerRange.data.values.length === 0) {
        // Add headers if they don't exist
        await sheets.spreadsheets.values.update({
          spreadsheetId,
          range: `${sheetName}!A1:J1`,
          valueInputOption: 'RAW',
          requestBody: {
            values: [
              [
                'Submission Time',
                'Team name',
                'Team id',
                'Leader name',
                'Leader\'s phone',
                'Leader\'s email',
                'Github link',
                'PPT link',
                'Video link',
                'Description',
              ],
            ],
          },
        });
      }
    }

    return sheetName;
  } catch (error) {
    console.error('[GOOGLE SHEETS] Error ensuring sheet exists:', error);
    throw error;
  }
};

/**
 * Find a row by teamId
 * Returns the row number (1-indexed) and data if found, null otherwise
 */
export const findRowByTeamId = async (teamId) => {
  try {
    const sheets = getSheetsClient();
    const spreadsheetId = getSpreadsheetId();
    const sheetName = await ensureSheetExists(sheets, spreadsheetId);

    // Get all values from the sheet
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: `${sheetName}!A:J`,
    });

    const values = response.data.values;
    if (!values || values.length < 2) {
      return null; // No data rows (only headers)
    }

    // Find the row with matching teamId (column C, index 2)
    // Column order: Submission Time (0), Team name (1), Team id (2), Leader name (3), Leader's phone (4), Leader's email (5), Github link (6), PPT link (7), Video link (8), Description (9)
    for (let i = 1; i < values.length; i++) {
      if (values[i][2] === teamId) {
        return {
          rowNumber: i + 1, // 1-indexed row number
          data: {
            submissionTime: values[i][0] || '',
            teamName: values[i][1] || '',
            teamId: values[i][2] || '',
            leaderName: values[i][3] || '',
            leaderPhone: values[i][4] || '',
            leaderEmail: values[i][5] || '',
            githubLink: values[i][6] || '',
            pptLink: values[i][7] || '',
            videoLink: values[i][8] || '',
            description: values[i][9] || '',
          },
        };
      }
    }

    return null;
  } catch (error) {
    console.error('[GOOGLE SHEETS] Error finding row by teamId:', error);
    throw error;
  }
};

/**
 * Add a new row to the sheet
 */
export const addRowToSheet = async (data) => {
  try {
    const sheets = getSheetsClient();
    const spreadsheetId = getSpreadsheetId();
    const sheetName = await ensureSheetExists(sheets, spreadsheetId);

    // Column order: Submission Time, Team name, Team id, Leader name, Leader's phone, Leader's email, Github link, PPT link, Video link, Description
    const values = [
      [
        data.submissionTime || '',
        data.teamName || '',
        data.teamId || '',
        data.leaderName || '',
        data.leaderPhone || '',
        data.leaderEmail || '',
        data.githubLink || '',
        data.pptLink || '',
        data.videoLink || '',
        data.description || '',
      ],
    ];

    // Append the row
    await sheets.spreadsheets.values.append({
      spreadsheetId,
      range: `${sheetName}!A:J`,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: {
        values,
      },
    });

    return { success: true, message: 'Data added to sheet successfully' };
  } catch (error) {
    console.error('[GOOGLE SHEETS] Error adding row to sheet:', error);
    throw error;
  }
};

/**
 * Update an existing row in the sheet
 */
export const updateRowInSheet = async (rowNumber, data) => {
  try {
    const sheets = getSheetsClient();
    const spreadsheetId = getSpreadsheetId();
    const sheetName = await ensureSheetExists(sheets, spreadsheetId);

    // Column order: Submission Time, Team name, Team id, Leader name, Leader's phone, Leader's email, Github link, PPT link, Video link, Description
    const values = [
      [
        data.submissionTime || '',
        data.teamName || '',
        data.teamId || '',
        data.leaderName || '',
        data.leaderPhone || '',
        data.leaderEmail || '',
        data.githubLink || '',
        data.pptLink || '',
        data.videoLink || '',
        data.description || '',
      ],
    ];

    // Update the row
    await sheets.spreadsheets.values.update({
      spreadsheetId,
      range: `${sheetName}!A${rowNumber}:J${rowNumber}`,
      valueInputOption: 'RAW',
      requestBody: {
        values,
      },
    });

    return { success: true, message: 'Data updated in sheet successfully' };
  } catch (error) {
    console.error('[GOOGLE SHEETS] Error updating row in sheet:', error);
    throw error;
  }
};

/**
 * Get submission data by teamId
 */
export const getSubmissionByTeamId = async (teamId) => {
  try {
    const result = await findRowByTeamId(teamId);
    return result ? result.data : null;
  } catch (error) {
    console.error('[GOOGLE SHEETS] Error getting submission by teamId:', error);
    throw error;
  }
};
